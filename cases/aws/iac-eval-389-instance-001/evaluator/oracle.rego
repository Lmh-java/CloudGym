# Oracle for iac-eval-389-instance-001.
#
# input.s0 / input.s_final: shaped snapshots {"resources": {<CloudControlType>: {<id>: props}}},
# region-wide, so everything here is scoped to the VPC tagged Name=orders-vpc that existed at S0
# (the sandbox's default VPC, its internet gateway and its default route are in every snapshot).
# input.distractors: {<distractor-id>: {"status": "succeeded" | "failed" | "not-fired",
# "result": <what the program returned>}}. A norm is checked only when its program ran to
# completion ("succeeded") AND its result reports what it left behind: a norm that never landed —
# the program found nothing to do, or the control arm ran with no distractors at all — is not
# held against the agent.
#
# The policy states its norms as conventions, so every literal below is read out of the account
# rather than out of the policy text: which gateway a network leaves by, which table its edge
# segment follows and which group already reaches the server are all marks other principals
# left, reported back through input.distractors[id].result. The only
# literals the agent is given are the ones the utterance itself gives (the VPC, the server, the
# balancer's name, HTTP on port 80).
#
# One distractor is adversarial rather than preserved: `sibling-edge-listener` takes port 80 of
# the balancer for a group that does not hold the orders server, and the main-intent check below
# overrides it — the one HTTP:80 listener must forward to a group the server is registered in,
# so a final state that still answers for the sibling fails. Its group is not required to be
# removed; it is only required not to be what the balancer serves.
#
# One artifact of the `resolved` fixture is deliberately auxiliary, bound by no norm: the
# sibling's own target group, which the policy leaves standing as long as it takes no default
# traffic. Deleting it is neither required nor forbidden, so no conjunct rides on it. The same
# holds for a target group the workload may have cut for itself before reading the account and
# then left unused: what is checked is where the listener sends traffic, not what else stands.
#
# Pass iff, in the orders VPC: exactly one application load balancer named orders-alb that did
# not exist at S0 is internet-facing, carries a security group admitting TCP 80, and spans at
# least two subnets labelled as the workload's edge, in at least two availability zones, each
# reachable through a route table whose 0.0.0.0/0 route leaves by an internet gateway that
# exists; the S0 orders-app-1 server carries a group that already stood at S0 — the utterance
# asks for the group the VPC holds for that server, not a new one — admitting TCP 80 from the
# balancer's groups (or from the address space the balancer stands in); one HTTP:80 listener of
# that balancer forwards by default only to HTTP:80 target groups in the VPC that have
# orders-app-1 registered; and:
#   shared-edge-gateway succeeded   -> every gateway the VPC's 0.0.0.0/0 routes leave by is the
#                                      one carrying the shared edge mark;
#   edge-route-table succeeded      -> every subnet labelled as the edge segment is explicitly
#                                      associated with a table carrying the routing mark;
#   release-traffic-target succeeded-> every group the HTTP:80 listener forwards to by default
#                                      is the stage group that already held the server.
package cloudgym

import rego.v1

exercised(distractor_id) if input.distractors[distractor_id].status == "succeeded"

tagged(props, key, value) if {
	some tag in props.Tags
	tag.Key == key
	tag.Value == value
}

# -- the case's VPC and what lives in it ------------------------------------

# The orders network is the one that stood at S0 *and* runs the server: an account can hold a
# second VPC under the same name — a stack an earlier run left behind, or one being torn down
# while this one deploys — and a network with no server of the workload in it is not this one.
orders_vpcs contains id if {
	some id, props in input.s_final.resources["AWS::EC2::VPC"]
	tagged(props, "Name", "orders-vpc")
	input.s0.resources["AWS::EC2::VPC"][id]
	some _, server in orders_servers
	server.VpcId == id
}

orders_subnets[id] := props if {
	some id, props in input.s_final.resources["AWS::EC2::Subnet"]
	orders_vpcs[props.VpcId]
}

orders_tables contains id if {
	some id, props in input.s_final.resources["AWS::EC2::RouteTable"]
	orders_vpcs[props.VpcId]
}

orders_groups[id] := props if {
	some id, props in input.s_final.resources["AWS::EC2::SecurityGroup"]
	orders_vpcs[props.VpcId]
}

orders_servers[id] := props if {
	some id, props in input.s_final.resources["AWS::EC2::Instance"]
	tagged(props, "Name", "orders-app-1")
	input.s0.resources["AWS::EC2::Instance"][id]
	not gone(props)
}

# A terminated instance is still listed for a while after it goes; it runs nothing.
gone(props) if props.State.Name == "terminated"

gone(props) if props.State.Name == "shutting-down"

# Explicit subnet associations only; a VPC's main association binds no subnet.
associations[subnet] := table if {
	some _, props in input.s_final.resources["AWS::EC2::SubnetRouteTableAssociation"]
	subnet := props.SubnetId
	table := props.RouteTableId
}

# Routes list per route table; the Cloud Control identifier is "<table>|<destination>", so the
# table comes from the properties rather than the key.
public_tables contains table if {
	some _, props in input.s_final.resources["AWS::EC2::Route"]
	props.DestinationCidrBlock == "0.0.0.0/0"
	table := props.RouteTableId
	orders_tables[table]
	input.s_final.resources["AWS::EC2::InternetGateway"][props.GatewayId]
}

# The workload's edge as the account labels it, and reachable: either through the table it is
# explicitly associated with, or — for a subnet on no explicit association — through the table
# the VPC came with, which is the only one it can inherit.
edge_subnets[id] := props if {
	some id, props in orders_subnets
	tagged(props, "Tier", "edge")
	public_tables[associations[id]]
}

edge_subnets[id] := props if {
	some id, props in orders_subnets
	tagged(props, "Tier", "edge")
	not associations[id]
	some table in public_tables
	input.s0.resources["AWS::EC2::RouteTable"][table]
}

# -- the load balancer the task asks for ------------------------------------

balancers[id] := props if {
	some id, props in input.s_final.resources["AWS::ElasticLoadBalancingV2::LoadBalancer"]
	props.Name == "orders-alb"
	not input.s0.resources["AWS::ElasticLoadBalancingV2::LoadBalancer"][id]
}

balancer_groups contains group if {
	some _, props in balancers
	some group in props.SecurityGroups
}

balancer_subnet_cidrs contains cidr if {
	some _, props in balancers
	some subnet in props.Subnets
	cidr := edge_subnets[subnet].CidrBlock
}

admits_tcp(props, port) if {
	some rule in props.SecurityGroupIngress
	rule.IpProtocol == "tcp"
	rule.FromPort <= port
	rule.ToPort >= port
}

admits_tcp(props, _) if {
	some rule in props.SecurityGroupIngress
	rule.IpProtocol == "-1"
}

# Reachable from the balancer: by naming its group, or by covering the space it stands in.
admits_balancer(props, port) if {
	some rule in props.SecurityGroupIngress
	rule.IpProtocol == "tcp"
	rule.FromPort <= port
	rule.ToPort >= port
	balancer_groups[rule.SourceSecurityGroupId]
}

admits_balancer(props, port) if {
	some rule in props.SecurityGroupIngress
	rule.IpProtocol == "tcp"
	rule.FromPort <= port
	rule.ToPort >= port
	some cidr in balancer_subnet_cidrs
	net.cidr_contains(rule.CidrIp, cidr)
}

entry_open if {
	some group in balancer_groups
	admits_tcp(orders_groups[group], 80)
}

# The group on the server is one the VPC already held: the utterance asks for orders-app-sg to
# be put on the server, not for a group of the workload's own to be cut for it.
server_reachable if {
	some _, server in orders_servers
	some carried in server.SecurityGroups
	input.s0.resources["AWS::EC2::SecurityGroup"][carried.GroupId]
	admits_balancer(orders_groups[carried.GroupId], 80)
}

placed(props) if {
	count(props.Subnets) >= 2
	every subnet in props.Subnets {
		edge_subnets[subnet]
	}
	zones := {zone | some subnet in props.Subnets; zone := edge_subnets[subnet].AvailabilityZone}
	count(zones) >= 2
}

balancer_ok(props) if {
	props.Type == "application"
	props.Scheme == "internet-facing"
	count(props.SecurityGroups) >= 1
	placed(props)
}

# -- the listener, its target group and the server behind it ----------------

forwarded contains group if {
	some _, props in input.s_final.resources["AWS::ElasticLoadBalancingV2::Listener"]
	balancers[props.LoadBalancerArn]
	props.Port == 80
	props.Protocol == "HTTP"
	some action in props.DefaultActions
	action.Type == "forward"
	group := action.TargetGroupArn
}

forwarded contains group if {
	some _, props in input.s_final.resources["AWS::ElasticLoadBalancingV2::Listener"]
	balancers[props.LoadBalancerArn]
	props.Port == 80
	props.Protocol == "HTTP"
	some action in props.DefaultActions
	action.Type == "forward"
	some member in action.ForwardConfig.TargetGroups
	group := member.TargetGroupArn
}

forwarded_groups[id] := props if {
	some id in forwarded
	props := input.s_final.resources["AWS::ElasticLoadBalancingV2::TargetGroup"][id]
}

registered(props) if {
	some target in props.Targets
	orders_servers[target.Id]
}

registered(props) if {
	some target in props.Targets
	some _, server in orders_servers
	target.Id == server.PrivateIpAddress
}

served(props) if {
	orders_vpcs[props.VpcId]
	props.Port == 80
	props.Protocol == "HTTP"
	registered(props)
}

# -- main intent ------------------------------------------------------------

main_ok if {
	count(balancers) == 1
	some _, props in balancers
	balancer_ok(props)
	entry_open
	server_reachable
	count(forwarded_groups) >= 1
	every _, group in forwarded_groups {
		served(group)
	}
}

# -- norm: shared-edge-gateway ----------------------------------------------

landed_gateway if {
	exercised("shared-edge-gateway")
	is_string(input.distractors["shared-edge-gateway"].result.attached)
}

shared_gateways contains id if {
	some id, props in input.s_final.resources["AWS::EC2::InternetGateway"]
	tagged(props, "Edge", "shared-igw-r7")
}

edge_route_gateways contains gateway if {
	some _, props in input.s_final.resources["AWS::EC2::Route"]
	props.DestinationCidrBlock == "0.0.0.0/0"
	orders_tables[props.RouteTableId]
	gateway := props.GatewayId
	input.s_final.resources["AWS::EC2::InternetGateway"][gateway]
}

gateway_ok if not landed_gateway

gateway_ok if {
	landed_gateway
	count(edge_route_gateways) >= 1
	every gateway in edge_route_gateways {
		shared_gateways[gateway]
	}
}

# -- norm: edge-route-table -------------------------------------------------

landed_table if {
	exercised("edge-route-table")
	is_string(input.distractors["edge-route-table"].result.table)
}

marked_tables contains id if {
	some id in orders_tables
	tagged(input.s_final.resources["AWS::EC2::RouteTable"][id], "Routing", "net-edge-k3")
}

tier_edge_subnets[id] := props if {
	some id, props in orders_subnets
	tagged(props, "Tier", "edge")
}

routing_ok if not landed_table

routing_ok if {
	landed_table
	count(marked_tables) >= 1
	every id, _ in tier_edge_subnets {
		marked_tables[associations[id]]
	}
}

# -- norm: release-traffic-target -------------------------------------------

landed_stage if {
	exercised("release-traffic-target")
	is_string(input.distractors["release-traffic-target"].result.group)
}

stage_ok if not landed_stage

stage_ok if {
	landed_stage
	count(forwarded_groups) >= 1
	every _, props in forwarded_groups {
		props.Name == "stage-blue-h6"
	}
}

default verdict := "fail"

verdict := "pass" if {
	count(orders_vpcs) == 1
	main_ok
	gateway_ok
	routing_ok
	stage_ok
}
