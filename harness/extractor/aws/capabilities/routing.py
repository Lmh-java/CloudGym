"""Capability adapters for VPC routing: internet gateway, route table, association, route.

Unblocked 2026-09-01 by the service-level SCP (infra/aws/sandbox-scp.json): ec2:* is
open, so these types are smokable. Quirk handled via ``tolerated_get_error``: the region-wide
``AWS::EC2::SubnetRouteTableAssociation`` listing includes every VPC's *main* association,
which has no subnet and whose GetResource fails — capture skips exactly those items.

Cloud Control facts (verified by the capability smoke):
* ``AWS::EC2::InternetGateway`` lists region-wide; its model carries no attachment info —
  the attachment lives on the Terraform side (``vpc_id``) and in EC2 describe calls.
* ``AWS::EC2::RouteTable`` lists region-wide; routes are NOT in its model.
* ``AWS::EC2::SubnetRouteTableAssociation`` lists region-wide (explicit associations only;
  the main association has no subnet and does not appear).
* ``AWS::EC2::Route`` lists per route table (``RouteTableId`` resource model), like
  ``AWS::Lambda::Permission`` lists per function; the implicit ``local`` route is included.
"""

from .base import CapabilityAdapter


class InternetGatewayAdapter(CapabilityAdapter):
    terraform_type = "aws_internet_gateway"
    cloudcontrol_type = "AWS::EC2::InternetGateway"
    semantic_properties = ("Tags",)
    volatile_fields = ("InternetGatewayId",)
    readiness_properties = ("InternetGatewayId",)

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        session.client("ec2").create_tags(Resources=[identifier], Tags=tags)
        return {"Tags": tags}


class RouteTableAdapter(CapabilityAdapter):
    terraform_type = "aws_route_table"
    cloudcontrol_type = "AWS::EC2::RouteTable"
    semantic_properties = ("VpcId", "Tags")
    volatile_fields = ("RouteTableId",)
    readiness_properties = ("RouteTableId", "VpcId")

    def smoke_mutation(self, session, identifier: str, properties: dict) -> dict | None:
        tags = [{"Key": "cloudgym-smoke", "Value": "mutation-visible"}]
        session.client("ec2").create_tags(Resources=[identifier], Tags=tags)
        return {"Tags": tags, "VpcId": properties.get("VpcId")}


class RouteTableAssociationAdapter(CapabilityAdapter):
    terraform_type = "aws_route_table_association"
    cloudcontrol_type = "AWS::EC2::SubnetRouteTableAssociation"
    semantic_properties = ("RouteTableId", "SubnetId")
    volatile_fields = ("Id",)
    readiness_properties = ("Id", "RouteTableId")

    def tolerated_get_error(self, identifier: str, error: Exception) -> bool:
        # The region-wide listing includes each VPC's *main* route-table association,
        # which has no subnet; GetResource on it fails. Skipping it loses nothing:
        # aws_route_table_association only ever binds explicit (subnet) associations.
        return "subnet" in str(error)


class RouteAdapter(CapabilityAdapter):
    terraform_type = "aws_route"
    cloudcontrol_type = "AWS::EC2::Route"
    semantic_properties = ("DestinationCidrBlock", "DestinationIpv6CidrBlock", "GatewayId",
                           "NatGatewayId", "TransitGatewayId", "VpcPeeringConnectionId",
                           "NetworkInterfaceId", "InstanceId")
    volatile_fields = ("RouteTableId", "CidrBlock")
    readiness_properties = ("RouteTableId",)
    list_parent = "AWS::EC2::RouteTable"

    def list_resource_model(self, parent_properties: dict) -> dict:
        return {"RouteTableId": parent_properties["RouteTableId"]}

    def get_error_means_absent(self, identifier: str, error: Exception) -> bool:
        # Once the parent route table is deleted, GetResource fails with
        # GeneralServiceException "The routeTable ID '...' does not exist" instead of
        # NotFound; a route cannot outlive its table.
        return "does not exist" in str(error)

    def identifier_from_state(self, attributes: dict) -> str:
        # Terraform's aws_route id is synthetic ("r-rtb..."); Cloud Control's is
        # "<RouteTableId>|<destination>".
        table = attributes.get("route_table_id")
        destination = (attributes.get("destination_cidr_block")
                       or attributes.get("destination_ipv6_cidr_block")
                       or attributes.get("destination_prefix_list_id"))
        if not table or not destination:
            raise ValueError(f"{self.terraform_type}: state needs route_table_id and a destination")
        return f"{table}|{destination}"
