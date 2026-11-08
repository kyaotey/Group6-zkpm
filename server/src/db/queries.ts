import type { QueryResult, QueryResultRow } from 'pg';

export interface DbPool {
  query<R extends QueryResultRow = any>(text: string, params?: any[]): Promise<QueryResult<R>>;
}

// Mock pool implementation allowing testing and safe execution without a live database instance
export let pool: DbPool = {
  async query<R extends QueryResultRow = any>(_text: string, _params?: any[]): Promise<QueryResult<R>> {
    return {
      rows: [] as R[],
      rowCount: 0,
      command: '',
      oid: 0,
      fields: [],
    };
  },
};

export function setPool(newPool: DbPool): void {
  pool = newPool;
}

export async function getVaultItem(userId: string, itemId: string) {
  const query = 'SELECT * FROM vault_items WHERE user_id = $1 AND id = $2';
  return pool.query(query, [userId, itemId]);
}

export async function createVaultItem(
  userId: string,
  itemId: string,
  type: string,
  title: string,
  encryptedBlob: string,
  iv: string
) {
  const query =
    'INSERT INTO vault_items (user_id, id, type, title, encrypted_blob, iv) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *';
  return pool.query(query, [userId, itemId, type, title, encryptedBlob, iv]);
}

export async function deleteVaultItem(userId: string, itemId: string) {
  const query = 'DELETE FROM vault_items WHERE user_id = $1 AND id = $2';
  return pool.query(query, [userId, itemId]);
}
