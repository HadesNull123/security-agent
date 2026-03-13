"""
LLM Factory - Creates LangChain LLM instances based on configuration.
Supports Gemini, OpenAI, Anthropic, and Ollama.
"""

from __future__ import annotations

import logging

from langchain_core.language_models import BaseChatModel

from src.core.config import Config, LLMProvider

logger = logging.getLogger(__name__)


def create_llm(config: Config) -> BaseChatModel:
    """
    Create a LangChain Chat LLM based on configuration.

    Args:
        config: Application configuration containing LLM settings.

    Returns:
        BaseChatModel instance ready for use.

    Raises:
        ValueError: If the provider is not supported or API key is missing.
    """
    provider = config.llm.provider
    model = config.llm.model
    temperature = config.llm.temperature
    max_tokens = config.llm.max_tokens

    logger.info(f"Initializing LLM: provider={provider.value}, model={model}")

    if provider == LLMProvider.GEMINI:
        if not config.llm.google_api_key:
            raise ValueError("GOOGLE_API_KEY is required for Gemini provider")
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model=model,
            google_api_key=config.llm.google_api_key,
            temperature=temperature,
            max_output_tokens=max_tokens,
        )

    elif provider == LLMProvider.OPENAI:
        if not config.llm.openai_api_key:
            raise ValueError("OPENAI_API_KEY is required for OpenAI provider")
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model,
            api_key=config.llm.openai_api_key,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    elif provider == LLMProvider.ANTHROPIC:
        if not config.llm.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY is required for Anthropic provider")
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=model,
            api_key=config.llm.anthropic_api_key,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    elif provider == LLMProvider.OLLAMA:
        from langchain_community.chat_models import ChatOllama
        return ChatOllama(
            model=config.llm.ollama_model,
            base_url=config.llm.ollama_base_url,
            temperature=temperature,
        )

    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")
