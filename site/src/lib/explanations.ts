export const explanations = {
  consulted:
    'Other participants change the infrastructure. The agent must consult them to discover how to resolve conflicts.',
  prompted:
    'Other participants change the infrastructure. Rules for resolving conflicts are provided in the agent’s prompt.',
  control:
    'The agent works alone, with no concurrent participants or interference.',
  hybrid:
    'The agent can freely combine Python scripts with the AWS SDK, command-line tools, and Terraform.',
  sc: 'Semantic conflict: two participants require incompatible outcomes. The agent must follow the resolution policy to decide which requirement takes precedence.',
  ia: 'Intent ambiguity: concurrent changes make the intended target or value unclear. The agent must clarify which outcome is intended.',
  ec: 'Execution conflict: participants have compatible goals, but overlapping operations temporarily block progress. The agent must wait, retry, or adapt.',
};
export type Explanation = keyof typeof explanations;
