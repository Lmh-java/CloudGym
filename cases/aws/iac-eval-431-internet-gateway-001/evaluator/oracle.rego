# Oracle for iac-eval-431-internet-gateway-001.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}},
# region-wide, so everything here is scoped to the VPC tagged Name=dgraph-vpc that existed at S0.
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A distractor's norm is checked only when its program ran to completion ("succeeded"): a norm
# that never landed — the program failed, or the control arm ran with no distractors — is not
# held against the agent, and the main-intent check alone must then be satisfiable.
#
# Pass iff, in dgraph-vpc: at least one route table that did not exist at S0 carries a Name tag
# and a 0.0.0.0/0 route leaving through an internet gateway that exists and is named, every such
# table satisfies the norms below, and:
#   kept-edge-gateway succeeded    -> every such table leaves through the gateway tagged
#                                     Name=acct-edge-igw, and no gateway outside S0 other than
#                                     that one stands in the account (a VPC holds one attached
#                                     gateway, and Cloud Control's gateway model carries no
#                                     attachment, so the route's target is what witnesses which
#                                     gateway won and what a second one would be doing there);
#   sibling-default-path succeeded -> the checkout segment still carries its app mark and the
#                                     path reference, and every table of the network carrying
#                                     that app mark still carries a 0.0.0.0/0 route aimed at the
#                                     same gateway the agent's table is aimed at — two default
#                                     routes aimed at different gateways cannot both reach out,
#                                     since only one gateway is attached. A table carries the app
#                                     mark only where the program opened that path, so a run in
#                                     which it opened none holds nothing against the agent;
#   edge-attribution succeeded     -> every such table carries the attribution the network
#                                     carries (CostCenter, as the VPC and its core segment show);
#   controlled-egress succeeded    -> every such table says it is a controlled path
#                                     (EgressPath=controlled, as the network and the gateway it
#                                     leaves through show).
# No distractor is adversarial here: every norm above is preserved, never overridden.
#
# Validator WARNs, justified: the staging directory is named `case` (publish renames it to the
# <slug>-NNN case id); seed_id is provenance only (the row-431 seed is minted at publish).
package cloudgym

import rego.v1

exercised(distractor_id) if input.distractors[distractor_id].status == "succeeded"

tagged(props, key, value) if {
	some tag in props.Tags
	tag.Key == key
	tag.Value == value
}

has_tag(props, key) if {
	some tag in props.Tags
	tag.Key == key
	tag.Value != ""
}

tag_value(props, key) := value if {
	some tag in props.Tags
	tag.Key == key
	value := tag.Value
}

# -- the case's network and what lives in it --------------------------------

app_vpcs[id] := props if {
	some id, props in input.s_final.resources["AWS::EC2::VPC"]
	tagged(props, "Name", "dgraph-vpc")
	input.s0.resources["AWS::EC2::VPC"][id]
}

app_subnets[id] := props if {
	some id, props in input.s_final.resources["AWS::EC2::Subnet"]
	app_vpcs[props.VpcId]
}

app_tables[id] := props if {
	some id, props in input.s_final.resources["AWS::EC2::RouteTable"]
	app_vpcs[props.VpcId]
}

# Routes list per route table; the Cloud Control identifier is "<table>|<destination>", so the
# table comes from the properties rather than the key.
default_routes[table] := gateway if {
	some _, props in input.s_final.resources["AWS::EC2::Route"]
	props.DestinationCidrBlock == "0.0.0.0/0"
	table := props.RouteTableId
	app_tables[table]
	gateway := props.GatewayId
}

gateways[id] := props if {
	some id, props in input.s_final.resources["AWS::EC2::InternetGateway"]
}

# -- main intent -----------------------------------------------------------

# The table the agent stood up: not there at S0, named, and carrying the network's way out
# through a gateway that really exists and is named.
way_out_tables[table] := props if {
	some table, props in app_tables
	not input.s0.resources["AWS::EC2::RouteTable"][table]
	has_tag(props, "Name")
	gateway := default_routes[table]
	has_tag(gateways[gateway], "Name")
}

way_out_gateways contains gateway if {
	some table, _ in way_out_tables
	gateway := default_routes[table]
}

table_ok if count(way_out_tables) >= 1

# -- norm: kept-edge-gateway -----------------------------------------------

kept_gateways[id] := props if {
	some id, props in gateways
	tagged(props, "Name", "acct-edge-igw")
}

second_gateway_standing if {
	some id, _ in gateways
	not input.s0.resources["AWS::EC2::InternetGateway"][id]
	not kept_gateways[id]
}

leaves_through_another if {
	some gateway in way_out_gateways
	not kept_gateways[gateway]
}

gateway_ok if not exercised("kept-edge-gateway")

gateway_ok if {
	exercised("kept-edge-gateway")
	not leaves_through_another
	not second_gateway_standing
}

# -- norm: sibling-default-path --------------------------------------------

sibling_tables[table] := props if {
	some table, props in app_tables
	tagged(props, "App", "checkout-web")
}

sibling_segments[id] := props if {
	some id, props in app_subnets
	tagged(props, "App", "checkout-web")
	tagged(props, "PathRef", "SIB-6605")
}

sibling_path_broken if {
	some table, _ in sibling_tables
	not default_routes[table]
}

sibling_path_broken if {
	some table, _ in sibling_tables
	some gateway in way_out_gateways
	default_routes[table] != gateway
}

sibling_ok if not exercised("sibling-default-path")

sibling_ok if {
	exercised("sibling-default-path")
	count(sibling_segments) >= 1
	not sibling_path_broken
}

# -- norm: edge-attribution ------------------------------------------------

network_attribution contains value if {
	some _, props in app_vpcs
	value := tag_value(props, "CostCenter")
}

charged_nowhere if {
	some _, props in way_out_tables
	some value in network_attribution
	not tagged(props, "CostCenter", value)
}

attribution_ok if not exercised("edge-attribution")

attribution_ok if {
	exercised("edge-attribution")
	count(network_attribution) >= 1
	not charged_nowhere
}

# -- norm: controlled-egress -----------------------------------------------

uncontrolled_way_out if {
	some _, props in way_out_tables
	not tagged(props, "EgressPath", "controlled")
}

control_ok if not exercised("controlled-egress")

control_ok if {
	exercised("controlled-egress")
	not uncontrolled_way_out
}

default verdict := "fail"

verdict := "pass" if {
	count(app_vpcs) == 1
	table_ok
	gateway_ok
	sibling_ok
	attribution_ok
	control_ok
}
