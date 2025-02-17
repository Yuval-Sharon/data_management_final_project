
import copy
from db_utils import DbConnection
import re
from typing import Tuple
import re
from typing import Tuple, List, Set, Dict
from db_utils import DbConnection
import sqlparse
from sqlparse.sql import Where, Comparison, Identifier, Function, Operation


class Query:
    def __init__(self, query_description, user_query, q_star_query):
        self.query_description = query_description
        self.user_query = user_query
        self.q_star_query = q_star_query
        self.db_connection = DbConnection()
        self.user_query_table_mapping = {}
        self.q_star_query_table_mapping = {}
        self.aliases_mapping = {}
    
    def set_user_query(self, user_query):
        self.user_query = user_query


    def execute_query(self):
        try:
            query_results = self.db_connection.fetch_all(self.user_query)
            return query_results
        except Exception as e:
            print(f"Error executing query")
            return []

    def execute_q_star_query(self):
        q_star_results = self.db_connection.fetch_all(self.q_star_query)
        return q_star_results

    def _get_table_names(self, query, user_query=True) -> List[Tuple[str, str]]:
        """
        Extract table names and their aliases from the query.
        Handles both comma-separated table lists in the FROM clause and explicit JOIN clauses.
        Returns a list of tuples: (table_name, alias) where alias is None if not specified.
        """
        tables = []
        query_lower = query.lower()

        # Extract the FROM clause: from 'FROM' until the first occurrence of 'JOIN' or 'WHERE' (or end of query).
        from_index = query_lower.find("from")
        if from_index != -1:
            end_index = len(query)
            for kw in [" join ", " where "]:
                idx = query_lower.find(kw, from_index)
                if idx != -1:
                    end_index = min(end_index, idx)
            from_clause = query[from_index + len("from"):end_index].strip()
            # Split on commas to get individual table specs.
            from_tables = [tbl.strip() for tbl in from_clause.split(",") if tbl.strip()]
            for spec in from_tables:
                # Remove any "AS" keyword.
                spec = re.sub(r'\bAS\b', '', spec, flags=re.IGNORECASE).strip()
                parts = spec.split()
                if parts:
                    table_name = parts[0]
                    alias = parts[1] if len(parts) > 1 else None
                    tables.append((table_name, alias))
        
        # Now extract JOIN clauses.
        # This regex will match JOIN followed by a table name and an optional alias.
        join_pattern = re.compile(r'\bJOIN\s+([^\s,]+)(?:\s+(?:AS\s+)?(\w+))?', re.IGNORECASE)
        join_matches = join_pattern.findall(query)
        for table, alias in join_matches:
            alias = alias if alias != '' else None
            tables.append((table, alias))
        
        if user_query:
            self.user_query_table_mapping = {alias: table for table, alias in tables}
        else:
            self.q_star_query_table_mapping = {alias: table for table, alias in tables}
        return tables

    def _get_columns_from_query(self, query) -> List[Tuple[str, str]]:
        """
        Extract columns from the query's SELECT clause.
        Returns a list of tuples (table_alias, column) by parsing the text between SELECT and FROM.
        """
        query_lower = query.lower()
        select_index = query_lower.find("select")
        from_index = query_lower.find("from", select_index)
        if select_index == -1 or from_index == -1:
            return []

        select_clause = query[select_index + len("select"):from_index].strip()
        select_clause = re.sub(r'\bDISTINCT\b', '', select_clause, flags=re.IGNORECASE).strip()
        column_specs = [col.strip() for col in select_clause.split(",") if col.strip()]
        columns = []
        for col in column_specs:
            col = col.split(" as ")[0].strip()  # Remove any alias after AS
            if '.' in col:
                table_alias, column_name = col.split('.', 1)
                columns.append((table_alias.strip(), column_name.strip()))
            else:
                columns.append((None, col))
        return columns

    @staticmethod
    def __multi_set_subtract(a, b):
        a_copy = copy.deepcopy(a)
        b_copy = copy.deepcopy(b)
        result = []
        for item in a_copy:
            if item in b_copy:
                b_copy.remove(item)
            else:
                result.append(item)
        return result
    
    def _check_from_clause(self) -> Tuple[List[str], List[str]]:
        user_tables = self._get_table_names(self.user_query, user_query=True)
        q_star_tables = self._get_table_names(self.q_star_query, user_query=False)
        user_multiset = list(t[0] for t in user_tables)
        q_star_multiset = list(t[0] for t in q_star_tables)
        missing_tables = self.__multi_set_subtract(q_star_multiset, user_multiset)
        extra_tables = self.__multi_set_subtract(user_multiset, q_star_multiset)
        print(f" user_multiset: {user_multiset}, q_star_multiset: {q_star_multiset}")
        print(f" missing_tables: {missing_tables}, extra_tables: {extra_tables}")
        return missing_tables, extra_tables

    def hint_for_repair_from_clause(self) -> Tuple[bool, str]:
        missing_tables, extra_tables = self._check_from_clause()
        print(missing_tables, extra_tables)
        if len(missing_tables) == 0 and len(extra_tables) == 0:
            return True, ""
        else:
            if len(missing_tables) > 0:
                return False, f"It seems like you are missing a table. Please check if you need to include {list(missing_tables)[0]} in your query."
            else:
                return False, f"It seems like you have an extra table. Please check if you need to exclude {list(extra_tables)[0]} from your query."

    def _map_aliases_between_queries(self):
        """
        Map all aliases between the user query and the q_star query based on selected columns.
        The heuristic is as follows:
          1. For each table present in both queries, group the aliases from the user query and q_star query.
          2. For each candidate pair (user_alias, q_star_alias), compute a score equal to the number
             of common column names (from the SELECT clause).
          3. Use a greedy matching on these candidate pairs (highest score first).
          4. For any remaining unmatched user alias, assign it an unused Q* alias (or if none remain, pick arbitrarily).
        The final mapping is stored in self.aliases_mapping as: user_alias -> q_star_alias.
        """
        # Group aliases by table name for both queries.
        user_table_aliases: Dict[str, Set[str]] = {}
        q_star_table_aliases: Dict[str, Set[str]] = {}

        user_tables = self._get_table_names(self.user_query, user_query=True)
        q_star_tables = self._get_table_names(self.q_star_query, user_query=False)

        for table, alias in user_tables:
            if alias is not None:
                user_table_aliases.setdefault(table, set()).add(alias)
        for table, alias in q_star_tables:
            if alias is not None:
                q_star_table_aliases.setdefault(table, set()).add(alias)

        # Group selected columns by alias.
        user_columns_by_alias: Dict[str, Set[str]] = {}
        q_star_columns_by_alias: Dict[str, Set[str]] = {}

        for alias, col in self._get_columns_from_query(self.user_query):
            if alias is not None:
                user_columns_by_alias.setdefault(alias, set()).add(col)
        for alias, col in self._get_columns_from_query(self.q_star_query):
            if alias is not None:
                q_star_columns_by_alias.setdefault(alias, set()).add(col)

        alias_mapping = {}
        # Process each table that appears in both queries.
        common_tables = set(user_table_aliases.keys()) & set(q_star_table_aliases.keys())
        for table in common_tables:
            # Sort aliases for deterministic behavior.
            user_aliases = sorted(list(user_table_aliases[table]))
            q_star_aliases = sorted(list(q_star_table_aliases[table]))
            
            # Build candidate pairs with scores.
            candidates = []
            for ua in user_aliases:
                for qa in q_star_aliases:
                    user_cols = user_columns_by_alias.get(ua, set())
                    q_cols = q_star_columns_by_alias.get(qa, set())
                    score = len(user_cols & q_cols)
                    candidates.append((score, ua, qa))
            # Sort candidates by descending score.
            candidates.sort(key=lambda x: x[0], reverse=True)
            matched_user = set()
            matched_q_star = set()
            # Greedy matching.
            for score, ua, qa in candidates:
                if ua not in matched_user and qa not in matched_q_star:
                    alias_mapping[ua] = qa
                    matched_user.add(ua)
                    matched_q_star.add(qa)
            # For any remaining user alias, assign an unused Q* alias (or arbitrarily assign one).
            for ua in user_aliases:
                if ua not in matched_user:
                    remaining = [qa for qa in q_star_aliases if qa not in matched_q_star]
                    if remaining:
                        alias_mapping[ua] = remaining[0]
                        matched_q_star.add(remaining[0])
                    else:
                        alias_mapping[ua] = q_star_aliases[0]
        self.aliases_mapping = alias_mapping

    def hint_for_repair_select_clause(self) -> Tuple[bool, str]:
        """
        1. Get the aliases mapping.
        2. Get the columns from the user query.
        3. Get the columns from the q_star query.
        4. Compare the columns (after mapping the user query aliases to Q* aliases) and return a hint.
        """
        # Step 1: Ensure the alias mapping is computed.
        self._map_aliases_between_queries()

        # Create a reverse mapping from Q* aliases to user aliases
        reverse_alias_mapping = {v: k for k, v in self.aliases_mapping.items()}

        # Step 2: Extract columns from user query.
        user_columns = self._get_columns_from_query(self.user_query)
        # Map each user alias to its corresponding Q* alias if available.
        mapped_user_columns = set()
        for alias, col in user_columns:
            if alias and alias in self.aliases_mapping:
                mapped_alias = self.aliases_mapping[alias]
            else:
                mapped_alias = alias  # No mapping available.
            mapped_user_columns.add((mapped_alias, col))
        
        # Step 3: Extract columns from q_star query.
        q_star_columns = set(self._get_columns_from_query(self.q_star_query))
        
        # Step 4: Compare the sets.
        missing = q_star_columns - mapped_user_columns
        extra = mapped_user_columns - q_star_columns

        if missing or extra:
            hint_parts = []
            
            if missing:
                # Convert Q* aliases back to user aliases for missing columns
                missing_user_columns = [
                    f"{reverse_alias_mapping.get(alias, alias)}.{col}" for alias, col in missing
                ]
                hint_parts.append(f"Missing columns: {', '.join(missing_user_columns)}.")
            
            if extra:
                # Convert Q* aliases back to user aliases for extra columns
                extra_user_columns = [
                    f"{reverse_alias_mapping.get(alias, alias)}.{col}" for alias, col in extra
                ]
                hint_parts.append(f"Extra columns: {', '.join(extra_user_columns)}.")
            
            hint_message = " ".join(hint_parts)
            return False, hint_message
        else:
            return True, ""
        
        
    def _extract_where_clause(self, query: str) -> str:
        """
        Extract the WHERE clause from the query.
        """
        where_index = query.lower().find("where")
        if where_index == -1:
            return ""
        return query[where_index + len("where"):].strip()
        
    def _build_where_syntax_tree(self, where_clause: str):
        """
        Build a syntax tree for the WHERE clause.
        """
        parsed = sqlparse.parse(where_clause)[0]
        
        def build_tree(token):
            if isinstance(token, Comparison):
                # Basic comparison (e.g., s.price < 5)
                return ("COMPARISON", str(token))
            elif isinstance(token, Operation):
                # Operation (e.g., A AND B)
                op = str(token.token_next_by_type(sqlparse.sql.Token.T_OPERATOR))
                left = token.token_first()
                right = token.token_last()
                return (op, build_tree(left), build_tree(right))
            elif isinstance(token, sqlparse.sql.Where):
                # Recursively process the Where clause
                _, sub_token = token.token_next_by_type(sqlparse.sql.Token)  # Skip the WHERE keyword itself
                return build_tree(sub_token)

            elif isinstance(token, sqlparse.sql.Identifier):
                return ("IDENTIFIER", str(token))
            elif isinstance(token, sqlparse.sql.Function):
                return ("FUNCTION", str(token))
            else:
                # Handle other token types as needed (e.g., IdentifierList, Parenthesis)
                return ("TOKEN", str(token))

        return build_tree(parsed)
    
    def _map_aliases_where_tree(self, tree):
        """
        Update WHERE tree with alias mapping
        """
        if isinstance(tree, tuple):
            node_type = tree[0]
            if node_type == 'COMPARISON':
                comparison_str = tree[1]
                # Use regex to find columns with table aliases in the comparison string
                pattern = re.compile(r'(\w+\.\w+)')
                matches = pattern.findall(comparison_str)
                for match in matches:
                    table_alias, column_name = match.split('.')

                    if table_alias in self.aliases_mapping:
                        mapped_alias = self.aliases_mapping[table_alias]
                        new_column_str = f"{mapped_alias}.{column_name}"
                        comparison_str = comparison_str.replace(match, new_column_str)  # Replace in the string
                return (node_type, comparison_str)
            else:
                # Recursively process the children of the node
                new_children = [self._map_aliases_where_tree(child) for child in tree[1:]]
                return (tree[0], *new_children)
        return tree
    
    def _compare_where_trees(self, tree1, tree2):
        """
        Compare two syntax trees recursively.

        Return a list of differences found. The differences are represented as a list of tuples,
        where each tuple contains the path to the differing node in tree1 and tree2, and the differing node information.
        """
        differences = []

        def compare_nodes(node1, node2, path1=(), path2=()):
            """
            Compare two nodes and their children.
            """
            if type(node1) != type(node2):
                differences.append((path1, path2, "Node types differ", node1, node2))
                return  # Stop further comparison if node types differ

            if isinstance(node1, tuple):  # For operator nodes
                if node1[0] != node2[0]:
                    differences.append((path1, path2, "Operators differ", node1[0], node2[0]))
                    return

                # Compare children
                for i in range(1, len(node1)):
                    compare_nodes(node1[i], node2[i], path1 + (f"child{i}",), path2 + (f"child{i}",))
            else:  # For leaf nodes (COMPARISON, IDENTIFIER, FUNCTION, TOKEN)
                if node1 != node2:
                    differences.append((path1, path2, "Leaf nodes differ", node1, node2))

        compare_nodes(tree1, tree2)
        return differences

    def _construct_where_hint(self, diffs):
        """
        Construct hint from list of differences
        """
        hint_message = ""
        for path1, path2, message, node1, node2 in diffs:
            if "Leaf nodes differ" in message:
                # Example logic: different predicate
                hint_message += f"The WHERE clause might be incorrect. Consider modifying `{node1}` to `{node2}`. "
            elif "Operators differ" in message:
                # Example logic: different operator
                hint_message += f"The operator might be incorrect. Consider changing `{node1}` to `{node2}`. "
            else:
                hint_message += "There is a difference in where clause."

        return hint_message

    def hint_for_repair_where_clause(self) -> Tuple[bool, str]:
        """
        Provide hints for the WHERE clause by comparing syntax trees.
        """
        # 1. Get WHERE clauses from both queries.
        user_where_clause = self._extract_where_clause(self.user_query)
        q_star_where_clause = self._extract_where_clause(self.q_star_query)

        # 2. Build syntax trees.
        user_tree = self._build_where_syntax_tree(user_where_clause)
        q_star_tree = self._build_where_syntax_tree(q_star_where_clause)

        # 3. Add Alias
        self._map_aliases_between_queries()
        mapped_user_tree = self._map_aliases_where_tree(user_tree)

        # 4. Compare the trees and generate a diff.
        diffs = self._compare_where_trees(mapped_user_tree, q_star_tree)

        # 5. Construct hint from the diff.
        hint = self._construct_where_hint(diffs)

        if hint:
            return False, hint
        else:
            return True, ""

    def check_query_and_provide_hints(self):
        valid, hint = self.hint_for_repair_from_clause()
        if not valid:
            return False, hint
        
        valid, hint = self.hint_for_repair_where_clause()
        if not valid:
            return False, hint
        
        valid, hint = self.hint_for_repair_select_clause()
        if not valid:
            return False, hint
        return True, ""
    
class Query1(Query):
    def __init__(self, user_query):
        desc = "Query 1: Find all the bars that serves beer that Alice likes."
        # Converted q_star_query with implicit join
        q_star_query = (
            "SELECT s.bar FROM Serves s, Likes l "
            "WHERE s.beer = l.beer AND l.drinker = 'Alice'"
        )
        if user_query is None or user_query == "":
            # set example for **Wrong** query (remains unchanged as it had no explicit join)
            user_query = "SELECT s.bar FROM Serves s WHERE s.beer = 'Alice'"
        super().__init__(desc, user_query=user_query, q_star_query=q_star_query)


class Query2(Query):
    def __init__(self, user_query):
        desc = "Query 2: find all of the bars that alice or bob frequents."
        # No join used here, so no changes needed.
        q_star_query = "SELECT f.bar FROM Frequents f WHERE f.drinker IN ('Alice', 'Bob')"
        if user_query is None or user_query == "":
            # set example for **Wrong** query
            user_query = "SELECT f.bar FROM Frequents f"
        super().__init__(desc, user_query=user_query, q_star_query=q_star_query)


class Query3(Query):
    def __init__(self, user_query):
        desc = "Query 7: Find all bars that serve at least two distinct beers priced under 5."
        # Converted q_star_query with implicit join
        q_star_query = (
            "SELECT DISTINCT s1.bar FROM Serves s1, Serves s2 "
            "WHERE s1.bar = s2.bar AND s1.beer <> s2.beer "
            "AND s1.price < 5 AND s2.price < 5"
        )
        if user_query is None or user_query == "":
            # set example for **Wrong** query (remains unchanged as it had no explicit join)
            user_query = "SELECT DISTINCT s1.bar FROM Serves s1"
        super().__init__(desc, user_query=user_query, q_star_query=q_star_query)


class Query4(Query):
    def __init__(self, user_query):
        desc = (
            "Query 8: Find all beers that are liked by a drinker and are served in a bar "
            "that the same drinker frequents."
        )
        # Converted q_star_query with implicit joins
        q_star_query = (
            "SELECT DISTINCT L.beer FROM Likes L, Frequents F, Serves S "
            "WHERE L.drinker = F.drinker AND F.bar = S.bar AND S.beer = L.beer"
        )
        if user_query is None or user_query == "":
            # Converted user_query with implicit join
            user_query = (
                "SELECT DISTINCT L.beer FROM Likes L, Frequents F "
                "WHERE L.drinker = F.drinker"
            )
        super().__init__(desc, user_query=user_query, q_star_query=q_star_query)


class Query5(Query):
    def __init__(self, user_query):
        desc = (
            "Query 5: Find all of the beers that are served in a price under 5. "
            "Show the bar, the beer name and the price."
        )
        # q_star_query remains unchanged since no join is used.
        q_star_query = "SELECT s.bar, s.beer, s.price FROM Serves s WHERE s.price < 5"
        if user_query is None or user_query == "":
            # Wrong query remains unchanged (omits beer field)
            user_query = "SELECT s.bar, s.price FROM Serves s WHERE s.price < 5"
        super().__init__(desc, user_query=user_query, q_star_query=q_star_query)
