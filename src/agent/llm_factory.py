"""
LLM Factory - Creates LangChain LLM instances based on configuration.
Supports Gemini, OpenAI, Anthropic, Ollama, and LM Studio.
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
        # Suppress FutureWarning from deprecated google.generativeai package
        # langchain_google_genai internally uses it; warning breaks terminal UI
        import warnings
        warnings.filterwarnings("ignore", category=FutureWarning, module="langchain_google_genai")
        warnings.filterwarnings("ignore", category=FutureWarning, module="google.generativeai")
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

    elif provider == LLMProvider.LMSTUDIO:
        # LM Studio exposes an OpenAI-compatible API at http://localhost:1234/v1
        # Use ChatOpenAI with custom base_url and a dummy API key
        lm_model = config.llm.lmstudio_model or model
        base_url = config.llm.lmstudio_base_url

        logger.info(f"Connecting to LM Studio at {base_url}, model={lm_model}")

        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=lm_model,
            base_url=base_url,
            api_key="lm-studio",  # LM Studio doesn't require a real key
            temperature=temperature,
            max_tokens=max_tokens,
        )

    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")

