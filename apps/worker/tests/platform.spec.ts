import { expect, it } from 'vitest';
import { doh, SubrequestBudget } from '../src/security';

// Live read-only platform probe: no account keys or private target data.
it('performs native Workers DoH for a public example domain', async () => {
  const answer = await doh('example.com', 'A', new SubrequestBudget());
  expect(answer.answers.length).toBeGreaterThan(0);
});
