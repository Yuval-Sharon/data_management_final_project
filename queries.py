"""
A model to include the queries for the user and the Q* results.
Each query should have the following attributes:
  - query description
  - user query (empty at first)
  - query results (empty at first)
  - Q* query
  - Q* results 

Reminder that our data model is :
# don't use subqueries at all
"""
import copy
from db_utils import DbConnection
import re
from typing import Tuple
# starting from abstract class
import re
from typing import Tuple, List, Set, Dict
from db_utils import DbConnection

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
        print(f"join_matches: {join_matches}")
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

    def check_query_and_provide_hints(self):
        """
        Excluding the repair from part
        """
        valid, hint = self.hint_for_repair_from_clause()
        if not valid:
            return False, hint
        valid, hint = self.hint_for_repair_select_clause()
        if not valid:
            return False, hint
        return True, ""


class Query1(Query):
    def __init__(self, user_query):
        desc = "Query 1: Find all the bars that serves beer that Alice likes."
        q_star_query = "SELECT s.bar FROM Serves s JOIN Likes l ON s.beer = l.beer WHERE l.drinker = 'Alice'"
        if user_query is None or user_query == "":
            # set example for **Wrong** query
            user_query = "SELECT s.bar FROM Serves s"
        super().__init__(desc, user_query=user_query, q_star_query=q_star_query)

class Query2(Query):
    def __init__(self, user_query):
        desc = "Query 2: find all of the bars that alice or bob frequents."
        q_star_query = "SELECT f.bar FROM Frequents f WHERE f.drinker IN ('Alice', 'Bob')"
        if user_query is None or user_query == "":
            # set example for **Wrong** query
            user_query = "SELECT f.bar FROM Frequents f"
        super().__init__(desc, user_query=user_query, q_star_query=q_star_query)

class Query3(Query):
    def __init__(self, user_query):
        desc = "Query 7: Find all bars that serve at least two distinct beers priced under 5."
        q_star_query = (
            "SELECT DISTINCT s1.bar FROM Serves s1 "
            "JOIN Serves s2 ON s1.bar = s2.bar AND s1.beer <> s2.beer "
            "WHERE s1.price < 5 AND s2.price < 5"
        )
        if user_query is None or user_query == "":
            # set example for **Wrong** query
            user_query = "SELECT DISTINCT s1.bar FROM Serves s1"
        super().__init__(desc, user_query=user_query, q_star_query=q_star_query)

class Query4(Query):
    def __init__(self, user_query):
        desc = ("Query 8: Find all beers that are liked by a drinker and are served in a bar "
                "that the same drinker frequents.")
        q_star_query = (
            "SELECT DISTINCT L.beer FROM Likes L "
            "JOIN Frequents F ON L.drinker = F.drinker "
            "JOIN Serves S ON F.bar = S.bar AND S.beer = L.beer"
        )
        if user_query is None or user_query == "":
            # set example for **Wrong** query
            print("setting default query for query 4")
            user_query = "SELECT DISTINCT L.beer FROM Likes L JOIN Frequents F ON L.drinker = F.drinker"
        super().__init__(desc, user_query=user_query, q_star_query=q_star_query)

class Query5(Query):
    def __init__(self, user_query):
        desc = "Query 5: Find all of the beers that are served in a price under 5. Show the bar, the beer name and the price."
        # Correct query selects both bar and beer
        q_star_query = "SELECT s.bar, s.beer, s.price FROM Serves s WHERE s.price < 5"
        if user_query is None or user_query == "":
            # Wrong query selects only the bar, omitting the beer field.
            user_query = "SELECT s.bar, s.price FROM Serves s WHERE s.price < 5"
        super().__init__(desc, user_query=user_query, q_star_query=q_star_query)
