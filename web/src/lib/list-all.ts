// SPDX-License-Identifier: Apache-2.0

// listAll reads every page of a List method: page fetches one page after a token, and the loop
// ends at the empty next-page token. Lists filter and sort in the browser, so they need all items;
// the API's largest page is 500 (docs/07-api.md, "Resource design").
export async function listAll<T>(page: (token: string) => Promise<{ items: T[]; next: string }>): Promise<T[]> {
  const out: T[] = [];
  let token = "";
  do {
    const r = await page(token);
    out.push(...r.items);
    token = r.next;
  } while (token);
  return out;
}

export const largestPage = 500;
