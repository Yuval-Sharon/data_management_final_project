import gradio as gr
from db_utils import DbConnection
from argparse import ArgumentParser
from queries import Query1, Query2, Query3, Query4, Query5

def parse_args():
    parser = ArgumentParser()
    parser.add_argument("--suggest-user-query", action="store_true")
    return parser.parse_args()

def tab_function(query_class, input_text, suggest_user_query):
    query_instance = query_class(input_text)
    valid, hint = query_instance.check_query_and_provide_hints()
    user_results = query_instance.execute_query()
    q_star_results = query_instance.execute_q_star_query()
    if valid:
        return f"Good job! your query is correct.", user_results, q_star_results
    else:
        return hint, user_results, q_star_results

args = parse_args()

with gr.Blocks() as demo:
    # Add the data model description above the tabs
    # Likes(drinker, beer), Frequents(drinker, bar), Serves(bar, beer, price).

    gr.Markdown("""
    # Data Management Course Final Project
    In this project, we present a tool that includes some of the logic from the paper:
    ### [Qr-Hint: Actionable Hints Towards Correcting Wrong SQL Queries](https://dl.acm.org/doi/10.1145/3654995)
    The tool is designed to help users correct their SQL queries by providing hints and suggestions.
    Note that that the tool assumes that that the user query is a valid SQL query.
    Please build your queries using aliases for tables, and when selecting columns, use the alias.
 
    ## Data Model
    Here is a description of the tables:
    - **Likes(drinker, beer)**: A table that contains the drinkers and the beers they like.
    - **Frequents(drinker, bar)**: A table that contains the drinkers and the bars they frequent.
    - **Serves(bar, beer, price)**: A table that contains the bars and the beers they serve and the price of the beer.
    """)

    with gr.Tabs():
        for i, QueryClass in enumerate([Query1, Query2, Query3, Query4, Query5], start=1):
            query_instance = QueryClass(None)
            with gr.TabItem(f"Query {i}"):
                gr.Markdown(query_instance.query_description)
                input_text = gr.Textbox(label=f"Enter Query", value=query_instance.user_query if args.suggest_user_query else "")
                submit_button = gr.Button("Submit")
                output = gr.Textbox(label=f"Hints:")
                user_query_results = gr.Dataframe(label="User Query Results")
                q_star_results = gr.Dataframe(label="Q* Results")
                submit_button.click(lambda text, qc=QueryClass: tab_function(qc, text, args.suggest_user_query), 
                                    inputs=input_text, 
                                    outputs=[output, user_query_results, q_star_results])

demo.launch(share=True)