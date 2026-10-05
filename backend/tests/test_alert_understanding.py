import asyncio

import pytest

from app.services.understanding import AlertUnderstanding
from app.services.investigator import InvestigationValidationError
from tests.test_hub_workflow import detection


class Provider:
    def __init__(self, iocs):
        self.iocs = iocs
    async def _complete(self, prompt, name, schema):
        assert "Untrusted evidence" in prompt
        assert schema["additionalProperties"] is False
        return {"summary": "Possible PowerShell execution", "attack_types": ["powershell"], "ioc_values": self.iocs}


def test_llm_summary_keeps_provenance_and_all_extracted_iocs():
    result = asyncio.run(AlertUnderstanding(Provider(["8.8.8.8"])).analyze(detection().alert, "hub:e1"))
    assert result["source_ref"] == "hub:e1" and result["attack_types"] == ["powershell"]
    assert result["classification_is_hypothesis"]
    assert any(item["value"] == "example.org" for item in result["iocs"])


def test_llm_cannot_invent_an_indicator():
    with pytest.raises(InvestigationValidationError, match="invented"):
        asyncio.run(AlertUnderstanding(Provider(["invented.example"])).analyze(detection().alert, "hub:e1"))
