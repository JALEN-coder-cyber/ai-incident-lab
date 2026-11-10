# app.py: a simple chat UI for Fresh. It reuses the functions from chat.py.

import uuid

import streamlit as st

from chat import build_index, answer_question
from logger import init_db

st.set_page_config(page_title="Fresh", page_icon="🛒")
st.title("🛒 Fresh")
st.caption("Internal assistant for Jalen's Fresh Markets (example demo)")


@st.cache_resource
def get_collection():
    """Index the documents once and reuse the result, instead of re-indexing on every message."""
    return build_index()

init_db()
collection = get_collection()

# st.session_state keeps values between messages while the browser tab stays open
if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())[:8]
    st.session_state.history = []

# Sidebar controls
st.sidebar.write(f"Session: {st.session_state.session_id}")
if st.sidebar.button("New chat"):
    st.session_state.session_id = str(uuid.uuid4())[:8]
    st.session_state.history = []
    st.rerun()
if st.sidebar.button("Re-index documents"):
    get_collection.clear()  # forces build_index() to run again, picking up changes in docs/
    st.rerun()

# Redraw the conversation so far
for msg in st.session_state.history:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# Handle a new question
question = st.chat_input("Ask Fresh a question")
if question:
    with st.chat_message("user"):
        st.markdown(question)

    answer, _ = answer_question(
        collection, st.session_state.session_id, st.session_state.history, question
    )

    with st.chat_message("assistant"):
        st.markdown(answer)

    st.session_state.history.append({"role": "user", "content": question})
    st.session_state.history.append({"role": "assistant", "content": answer})