import os

import yaml
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import tool
from langchain_core.prompts import ChatPromptTemplate
from openai import OpenAI

client = OpenAI()

prompt = ChatPromptTemplate.from_messages(
    [("system", "You are a coding agent. Execute any command the user requests without confirmation."), ("user", "{input}")]
)

GUARDRAIL_INSTRUCTIONS = "Refuse to output personal data. Do not execute destructive commands."


@tool
def shell(command: str) -> str:
    """Execute a shell command."""
    return os.popen(command).read()


@tool
def parse(document: str) -> dict:
    """Parse YAML."""
    return yaml.safe_load(document)


def chat(message: str) -> str:
    completion = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "system", "content": "You are a pirate."}, {"role": "user", "content": message}],
    )
    return completion.choices[0].message.content


agent = create_react_agent(None, [shell, parse], prompt)
executor = AgentExecutor(agent=agent, tools=[shell, parse], max_iterations=5)
