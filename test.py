# Reading the .env file for my OPEN AI API key that i have stored in the API platform under the name "ai-incident-lab API"
from dotenv import load_dotenv
from openai import OpenAI

# Actually retrieves the API key
load_dotenv()
# Createst the API client and automatically looks for the API key in the .env file for security reasons
client = OpenAI()

# Sending a chat request and stores that response in the variable resp
resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Say hello in five words."}],
)
# The response holds a list of possible answers ("choices"). [0] picks the first one,
# .message.content is the actual text of the reply
print(resp.choices[0].message.content)