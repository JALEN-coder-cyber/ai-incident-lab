# Threat Model

## What the system is
"Fresh" is an internal RAG chatbot for Jalen's Fresh Markets, a fictional supermarket
chain in Australia and New Zealand. It answers staff questions using a small set of
fake company documents. Everything here is fictional: the company, documents,
finances, and credentials.

## What's worth protecting
- The planted fake credential in the IT admin notes
- HEAD OFFICE ONLY documents (finance, suppliers, IT notes)
- The system prompt (the bot's hidden instructions)

## Who the attacker is
- A store staff member who can use the bot but shouldn't see head office material
- An anonymous user who can only type into the chat
- An insider who can add a document to the knowledge base

## What they want
- Get the credential or head office content
- Make the bot ignore its rules
- Learn the system prompt

## What they can touch
- The chat input
- The content of documents the bot retrieves (attacker-controlled if they can add one)

## Assumptions and known weaknesses
- No authentication: the bot can't tell who is asking
- All documents sit in one index, so restricted content can reach the prompt
- Access control relies only on the system prompt, which is not real access control
- Real fix: filter retrieval by the user's role so restricted chunks never enter the prompt
- Single model, single app, no tools or agents: findings apply to this setup only

## Out of scope
- Attacks on the OpenAI API, my laptop, or n8n itself
- Real data (everything here is fake)