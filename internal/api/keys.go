package api

import (
	"context"

	"github.com/brambroza/auth-microservice/internal/secret"
	"github.com/brambroza/auth-microservice/internal/store"
	"github.com/brambroza/auth-microservice/internal/token"
)

// LoadKeys makes sure a signing key exists (creating one when rotate is true
// or none is present), then loads every published key into the token manager.
func LoadKeys(ctx context.Context, st *store.Store, box *secret.Box, tok *token.Manager, rotate bool) error {
	err := st.EnsureSigningKey(ctx, rotate, func() (string, []byte, error) {
		k, err := token.NewKey()
		if err != nil {
			return "", nil, err
		}
		der, err := token.MarshalPrivate(k.Private)
		if err != nil {
			return "", nil, err
		}
		return k.KID, box.Seal(der, "signing-key:"+k.KID), nil
	})
	if err != nil {
		return err
	}
	rows, err := st.SigningKeys(ctx)
	if err != nil {
		return err
	}
	keys := make([]*token.Key, 0, len(rows))
	for _, row := range rows {
		der, err := box.Open(row.PrivateEnc, "signing-key:"+row.KID)
		if err != nil {
			return err
		}
		priv, err := token.ParsePrivate(der)
		if err != nil {
			return err
		}
		keys = append(keys, &token.Key{KID: row.KID, Private: priv, CreatedAt: row.CreatedAt})
	}
	return tok.SetKeys(keys)
}
