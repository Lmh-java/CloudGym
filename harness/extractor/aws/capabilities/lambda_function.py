"""Capability adapter for ``aws_lambda_function``."""

from .base import CapabilityAdapter


class LambdaFunctionAdapter(CapabilityAdapter):
    terraform_type = "aws_lambda_function"
    cloudcontrol_type = "AWS::Lambda::Function"
    semantic_properties = (
        "Architectures",
        "CodeSigningConfigArn",
        "DeadLetterConfig",
        "Description",
        "Environment",
        "EphemeralStorage",
        "FileSystemConfigs",
        # FunctionName is the identifier, but unlike generated ids it is
        # user-chosen in every case Terraform, so it stays semantic.
        "FunctionName",
        "Handler",
        "ImageConfig",
        "KmsKeyArn",
        "Layers",
        "LoggingConfig",
        "MemorySize",
        "PackageType",
        "RecursiveLoop",
        "ReservedConcurrentExecutions",
        "Role",  # rewritten to a logical address during normalization
        "Runtime",
        "RuntimeManagementConfig",
        "SnapStart",
        "Tags",
        "Timeout",
        "TracingConfig",
        "VpcConfig",
    )
    volatile_fields = (
        "Arn",
        "SnapStartResponse",
        # Code is write-only; the read handler never returns the package.
        "Code",
    )
    readiness_properties = ("FunctionName", "Arn", "Role", "Runtime")
