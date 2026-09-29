"""Capability adapter for ``aws_lexv2models_bot``.

Added 2026-09-23 (rows 51, 52). Needs ``lex:*`` in the sandbox SCP; a bot is billed per
request, so an idle one is free. Cloud Control ``AWS::Lex::Bot`` reads it by id (Terraform's
id). Locales are separate Terraform resources and write-only on this type. Bot and locale
status (Creating, Building, Available, ...) are observed natively by the refusal catalogue;
the SDK ships waiters for them (``BotAvailable``, ``BotLocaleBuilt``).
"""

from .base import CapabilityAdapter


class LexV2BotAdapter(CapabilityAdapter):
    terraform_type = "aws_lexv2models_bot"
    cloudcontrol_type = "AWS::Lex::Bot"
    semantic_properties = ("BotTags", "BotType", "DataPrivacy", "Description", "ErrorLogSettings",
                           "IdleSessionTTLInSeconds", "Name", "RoleArn")
    volatile_fields = ("Arn", "Id")
    readiness_properties = ("Id", "Name", "RoleArn")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        lex = session.client("lexv2-models")
        bot = lex.describe_bot(botId=identifier)
        lex.update_bot(botId=identifier, botName=bot["botName"], roleArn=bot["roleArn"],
                       dataPrivacy=bot["dataPrivacy"], idleSessionTTLInSeconds=bot["idleSessionTTLInSeconds"],
                       description="cloudgym-smoke mutation-visible")
        return {"Description": "cloudgym-smoke mutation-visible"}
