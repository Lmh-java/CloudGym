# Oracle for iac-eval-432-internet-gateway-001.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}},
# region-wide, so everything here is scoped to the VPC tagged Name=dgraph-vpc that existed at S0.
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired", ...}}.
# A distractor's norm is checked only when its program ran to completion ("succeeded"): a norm
# that never landed — the program failed, or the control arm ran with no distractors — is not
# held against the agent, and the main-intent check alone must then be satisfiable.
#
# Pass iff, in dgraph-vpc: it resolves DNS and hands out DNS hostnames, and the segment that
# existed at S0 under Name=dgraph-edge-a is explicitly associated with a route table of the VPC
# that carries a 0.0.0.0/0 route through an internet gateway that is really there, with a Name
# tag on both that table and that gateway; and:
#   kept-way-out-gateway succeeded -> the table that segment rides leaves through the gateway
#                                     tagged Name=shared-way-out-igw under EgressRef=PLT-4417 (a
#                                     VPC holds one attached gateway, and Cloud Control's gateway
#                                     model carries no attachment, so the route's target is what
#                                     witnesses which gateway won the attachment);
#   kept-edge-table succeeded      -> exactly one table in the VPC carries a 0.0.0.0/0 route and
#                                     it is the one, and only one, carrying Routing=kept-outward
#                                     under RoutingRef=NET-3308;
#   closed-core-tier succeeded     -> every segment of the VPC carrying Isolation=closed-tier
#                                     under IsolationRef=SEC-8812 is still explicitly associated
#                                     with a table of the VPC that carries no way out;
#   ingest-egress-slice succeeded  -> every segment of the VPC carrying Slice=ingest-slice under
#                                     SliceRef=APP-9915 is explicitly associated with a table
#                                     that does carry the way out.
# No distractor is adversarial here: every norm above is preserved, never overridden.
#
# Validator WARN, justified: the fixture check reports that four artifacts could be deleted from
# `resolved` and the verdict would still pass — the table the sibling parks its segment on
# (Name=ingest-parked-rt) and the `local` route EC2 creates with each of the three tables nobody
# routes the way out on. All four are auxiliary by construction: the parked table is where the
# slice waits while the network has nowhere to go and holds nothing once the slice rides the way
# out, and a local route is made by EC2 with its table and is not something an agent writes or
# can remove. No norm is about any of them: `ingest-egress-slice` requires only that its segment
# leaves by the way out, and `closed-core-tier` only that its segment rides a table that carries
# none.
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

# -- the case's network and what lives in it -------------------------------

app_vpcs contains id if {
	some id, props in input.s_final.resources["AWS::EC2::VPC"]
	tagged(props, "Name", "dgraph-vpc")
	input.s0.resources["AWS::EC2::VPC"][id]
}

resolving contains id if {
	some id, props in input.s_final.resources["AWS::EC2::VPC"]
	app_vpcs[id]
	props.EnableDnsSupport == true
	props.EnableDnsHostnames == true
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

# A table whose default route leaves through a gateway that is really there.
way_out_tables contains table if {
	some table, gateway in default_routes
	input.s_final.resources["AWS::EC2::InternetGateway"][gateway]
}

# The same, and both the table and the gateway carry a Name tag.
named_way_out contains table if {
	some table in way_out_tables
	has_tag(app_tables[table], "Name")
	has_tag(input.s_final.resources["AWS::EC2::InternetGateway"][default_routes[table]], "Name")
}

# Explicit subnet associations only; a VPC's main association binds no subnet.
associations[subnet] := table if {
	some _, props in input.s_final.resources["AWS::EC2::SubnetRouteTableAssociation"]
	subnet := props.SubnetId
	table := props.RouteTableId
}

# -- main intent -----------------------------------------------------------

dns_ok if {
	some id in app_vpcs
	resolving[id]
}

edge_segments[id] := props if {
	some id, props in app_subnets
	tagged(props, "Name", "dgraph-edge-a")
	input.s0.resources["AWS::EC2::Subnet"][id]
}

segment_ok if {
	count(edge_segments) == 1
	some id, _ in edge_segments
	named_way_out[associations[id]]
}

# -- norm: kept-way-out-gateway --------------------------------------------

kept_gateways contains id if {
	some id, props in input.s_final.resources["AWS::EC2::InternetGateway"]
	tagged(props, "Name", "shared-way-out-igw")
	tagged(props, "EgressRef", "PLT-4417")
}

gateway_ok if not exercised("kept-way-out-gateway")

gateway_ok if {
	exercised("kept-way-out-gateway")
	some id, _ in edge_segments
	kept_gateways[default_routes[associations[id]]]
}

# -- norm: kept-edge-table -------------------------------------------------

kept_tables contains table if {
	some table, props in app_tables
	tagged(props, "Routing", "kept-outward")
	tagged(props, "RoutingRef", "NET-3308")
}

routing_ok if not exercised("kept-edge-table")

routing_ok if {
	exercised("kept-edge-table")
	count(kept_tables) == 1
	count(default_routes) == 1
	some table, _ in default_routes
	kept_tables[table]
}

# -- norm: closed-core-tier ------------------------------------------------

closed_segments[id] := props if {
	some id, props in app_subnets
	tagged(props, "Isolation", "closed-tier")
	tagged(props, "IsolationRef", "SEC-8812")
}

# The tier stays closed: the segment is still carried by a table of this network, and that
# table has no way out.
closed_still_closed contains id if {
	some id, _ in closed_segments
	table := associations[id]
	app_tables[table]
	not way_out_tables[table]
}

isolation_ok if not exercised("closed-core-tier")

isolation_ok if {
	exercised("closed-core-tier")
	count(closed_segments) >= 1
	count(closed_still_closed) == count(closed_segments)
}

# -- norm: ingest-egress-slice ---------------------------------------------

slice_segments[id] := props if {
	some id, props in app_subnets
	tagged(props, "Slice", "ingest-slice")
	tagged(props, "SliceRef", "APP-9915")
}

slice_riding contains id if {
	some id, _ in slice_segments
	way_out_tables[associations[id]]
}

slice_ok if not exercised("ingest-egress-slice")

slice_ok if {
	exercised("ingest-egress-slice")
	count(slice_segments) >= 1
	count(slice_riding) == count(slice_segments)
}

default verdict := "fail"

verdict := "pass" if {
	count(app_vpcs) == 1
	dns_ok
	segment_ok
	gateway_ok
	routing_ok
	isolation_ok
	slice_ok
}
