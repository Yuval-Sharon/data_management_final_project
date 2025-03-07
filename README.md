# Data Management Course Final Project
## The Project is based on the paper : [Qr-Hint: Actionable Hints Towards Correcting Wrong SQL Queries](https://dl.acm.org/doi/10.1145/3654995)
This project implements a simple interactive web application for validating and suggesting fixes to SQL queries.
It focuses on SPJ (SELECT-PROJECT-JOIN) queries with support for basic SELECT, FROM, and WHERE clauses.
The system uses a small example SQLite database to verify query correctness and to provide user query suggestions via a Gradio-based web interface.

## Setup

1. **Python Environment**  
   Configure a Python environment with the required packages:
   - `gradio`
   - `pandas`
   - `sqlite3`
   - `sqlparse`

2. **Database Creation**  
   Run the `create_db.py` script to create the SQLite database and populate it with fake data:
   ```sh
   python create_db.py

## How to Run the Project

* **With User Query Suggestions:**
If you want to see the user query suggestions when starting the app, run:
```sh
python app.py --suggest-user-query
```
* **Without User Query Suggestions:**
If you prefer to start the app without user query suggestions, run:
```sh
python app.py
```

## Project Overview
### Aplication Interface
* The web interface is built using Gradio, providing an easy way for users to interact with the system.
* SQL queries are executed against an SQLite database.
* A small example database is included to demonstrate and verify how the queries work.

### Main Logic Components
* **SELECT and FROM Clauses:**
The implementation for the SELECT and FROM clauses follows the high-level ideas from the research paper as closely as possible. It extracts table names (and their aliases) and selected columns from both the user’s query and the reference (q*) query. 

* **WHERE Clause:**
For the WHERE clause, a simplified version of the paper’s ideas is implemented:
    - **Syntax Tree Construction:** A syntax tree is built from the WHERE clause using `sqlparse`. This tree represents the structure of the predicate (conditions and logical operators).
    - **Alias Mapping:** Before further processing, the system maps table aliases in the user query to match those in the reference query (q*). This ensures consistency between the two queries.
    - **Normalization:** The syntax tree is normalized by flattening compound predicates (using AND/OR), converting certain constructs into equivalent forms.
    - **Fix Suggestions:** The differences found in the normalized trees are used to generate subtle hints for the user. For example, if a numeric constant is off in one predicate, the system will suggest reviewing that predicate without exposing the underlying syntax tree details.

## Summary
This project demonstrates a practical approach to query validation and user query suggestion for a subset of SQL queries. It combines:
* A Gradio interface for user interaction
* SQLite for query execution
* SQL parsing and normalization techniques for comparing and correcting user queries

While this implementation focuses on basic SPJ queries and a simplified WHERE clause correction, it provides a strong foundation for further extension and refinement.