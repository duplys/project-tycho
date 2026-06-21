from __future__ import annotations

from langchain_openai import ChatOpenAI

from researcher.config import ResearcherSettings


def build_llm(settings: ResearcherSettings) -> ChatOpenAI:
    return ChatOpenAI(
        model=settings.llm_model,
        temperature=settings.llm_temperature,
    )
