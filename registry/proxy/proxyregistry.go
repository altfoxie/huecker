package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"time"

	"github.com/c-robinson/iplib"

	"github.com/distribution/reference"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/configuration"
	"github.com/distribution/distribution/v3/internal/client"
	"github.com/distribution/distribution/v3/internal/client/auth"
	"github.com/distribution/distribution/v3/internal/client/auth/challenge"
	"github.com/distribution/distribution/v3/internal/client/transport"
	"github.com/distribution/distribution/v3/internal/dcontext"
	"github.com/distribution/distribution/v3/registry/proxy/scheduler"
	"github.com/distribution/distribution/v3/registry/storage"
	"github.com/distribution/distribution/v3/registry/storage/driver"
)

var repositoryTTL = 24 * 7 * time.Hour

// proxyingRegistry fetches content from a remote registry and caches it locally
type proxyingRegistry struct {
	embedded       distribution.Namespace // provides local registry functionality
	scheduler      *scheduler.TTLExpirationScheduler
	ttl            *time.Duration
	remoteURL      url.URL
	authChallenger authChallenger
	basicAuth      auth.CredentialStore
	subnet         iplib.Net6
	closeInterval  time.Duration
}

// NewRegistryPullThroughCache creates a registry acting as a pull through cache
func NewRegistryPullThroughCache(ctx context.Context, registry distribution.Namespace, driver driver.StorageDriver, config configuration.Proxy) (distribution.Namespace, error) {
	remoteURL, err := url.Parse(config.RemoteURL)
	if err != nil {
		return nil, err
	}

	v := storage.NewVacuum(ctx, driver)

	var s *scheduler.TTLExpirationScheduler
	var ttl *time.Duration
	if config.TTL == nil {
		// Default TTL is 7 days
		ttl = &repositoryTTL
	} else if *config.TTL > 0 {
		ttl = config.TTL
	} else {
		// TTL is disabled, never expire
		ttl = nil
	}

	if ttl != nil {
		s = scheduler.New(ctx, driver, "/scheduler-state.json")
		s.OnBlobExpire(func(ref reference.Reference) error {
			var r reference.Canonical
			var ok bool
			if r, ok = ref.(reference.Canonical); !ok {
				return fmt.Errorf("unexpected reference type : %T", ref)
			}

			repo, err := registry.Repository(ctx, r)
			if err != nil {
				return err
			}

			blobs := repo.Blobs(ctx)

			// Clear the repository reference and descriptor caches
			err = blobs.Delete(ctx, r.Digest())
			if err != nil {
				return err
			}

			err = v.RemoveBlob(r.Digest().String())
			if err != nil {
				return err
			}

			return nil
		})

		s.OnManifestExpire(func(ref reference.Reference) error {
			var r reference.Canonical
			var ok bool
			if r, ok = ref.(reference.Canonical); !ok {
				return fmt.Errorf("unexpected reference type : %T", ref)
			}

			repo, err := registry.Repository(ctx, r)
			if err != nil {
				return err
			}

			manifests, err := repo.Manifests(ctx)
			if err != nil {
				return err
			}
			err = manifests.Delete(ctx, r.Digest())
			if err != nil {
				return err
			}
			return nil
		})

		err = s.Start()
		if err != nil {
			return nil, err
		}
	}

	cs, b, err := configureAuth(config.Username, config.Password, config.RemoteURL)
	if err != nil {
		return nil, err
	}

	return &proxyingRegistry{
		embedded:  registry,
		scheduler: s,
		ttl:       ttl,
		remoteURL: *remoteURL,
		authChallenger: &remoteAuthChallenger{
			remoteURL: *remoteURL,
			cm:        challenge.NewSimpleManager(),
			cs:        cs,
		},
		basicAuth:     b,
		subnet:        iplib.NewNet6(net.ParseIP(config.Subnet), config.SubnetMaskLength, 0),
		closeInterval: config.CloseInterval,
	}, nil
}

func (pr *proxyingRegistry) Scope() distribution.Scope {
	return distribution.GlobalScope
}

func (pr *proxyingRegistry) Repositories(ctx context.Context, repos []string, last string) (n int, err error) {
	return pr.embedded.Repositories(ctx, repos, last)
}

func (pr *proxyingRegistry) Repository(ctx context.Context, name reference.Named) (distribution.Repository, error) {
	c := pr.authChallenger

	trans := http.DefaultTransport.(*http.Transport).Clone()
	go func() {
		t := time.NewTicker(pr.closeInterval)
		for range t.C {
			log.Println("huecker: CloseIdleConnections")
			trans.CloseIdleConnections()
		}
	}()

	trans.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		newAddr := pr.subnet.RandomIP()
		log.Println("huecker: Random IP", newAddr.String())

		dialer := &net.Dialer{
			Control: func(network, address string, c syscall.RawConn) error {
				var operr error
				if err := c.Control(func(fd uintptr) {
					operr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_FREEBIND, 1)
				}); err != nil {
					return err
				}
				return operr
			},
			LocalAddr: &net.TCPAddr{
				IP: newAddr,
			},
		}

		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			log.Println("huecker: DialContext error", err)
		}
		return conn, err
	}

	tkopts := auth.TokenHandlerOptions{
		Transport:   trans,
		Credentials: c.credentialStore(),
		Scopes: []auth.Scope{
			auth.RepositoryScope{
				Repository: name.Name(),
				Actions:    []string{"pull"},
			},
		},
		Logger: dcontext.GetLogger(ctx),
	}

	tr := transport.NewTransport(trans,
		auth.NewAuthorizer(c.challengeManager(),
			auth.NewTokenHandlerWithOptions(tkopts),
			auth.NewBasicHandler(pr.basicAuth)))

	localRepo, err := pr.embedded.Repository(ctx, name)
	if err != nil {
		return nil, err
	}
	localManifests, err := localRepo.Manifests(ctx, storage.SkipLayerVerification())
	if err != nil {
		return nil, err
	}

	remoteRepo, err := client.NewRepository(name, pr.remoteURL.String(), tr)
	if err != nil {
		return nil, err
	}

	remoteManifests, err := remoteRepo.Manifests(ctx)
	if err != nil {
		return nil, err
	}

	return &proxiedRepository{
		blobStore: &proxyBlobStore{
			localStore:     localRepo.Blobs(ctx),
			remoteStore:    remoteRepo.Blobs(ctx),
			scheduler:      pr.scheduler,
			ttl:            pr.ttl,
			repositoryName: name,
			authChallenger: pr.authChallenger,
		},
		manifests: &proxyManifestStore{
			repositoryName:  name,
			localManifests:  localManifests, // Options?
			remoteManifests: remoteManifests,
			ctx:             ctx,
			scheduler:       pr.scheduler,
			ttl:             pr.ttl,
			authChallenger:  pr.authChallenger,
		},
		name: name,
		tags: &proxyTagService{
			localTags:      localRepo.Tags(ctx),
			remoteTags:     remoteRepo.Tags(ctx),
			authChallenger: pr.authChallenger,
		},
	}, nil
}

func (pr *proxyingRegistry) Blobs() distribution.BlobEnumerator {
	return pr.embedded.Blobs()
}

func (pr *proxyingRegistry) BlobStatter() distribution.BlobStatter {
	return pr.embedded.BlobStatter()
}

type Closer interface {
	// Close release all resources used by this object
	Close() error
}

func (pr *proxyingRegistry) Close() error {
	return pr.scheduler.Stop()
}

// authChallenger encapsulates a request to the upstream to establish credential challenges
type authChallenger interface {
	tryEstablishChallenges(context.Context) error
	challengeManager() challenge.Manager
	credentialStore() auth.CredentialStore
}

type remoteAuthChallenger struct {
	remoteURL url.URL
	sync.Mutex
	cm challenge.Manager
	cs auth.CredentialStore
}

func (r *remoteAuthChallenger) credentialStore() auth.CredentialStore {
	return r.cs
}

func (r *remoteAuthChallenger) challengeManager() challenge.Manager {
	return r.cm
}

// tryEstablishChallenges will attempt to get a challenge type for the upstream if none currently exist
func (r *remoteAuthChallenger) tryEstablishChallenges(ctx context.Context) error {
	r.Lock()
	defer r.Unlock()

	remoteURL := r.remoteURL
	remoteURL.Path = "/v2/"
	challenges, err := r.cm.GetChallenges(remoteURL)
	if err != nil {
		return err
	}

	if len(challenges) > 0 {
		return nil
	}

	// establish challenge type with upstream
	if err := ping(r.cm, remoteURL.String(), challengeHeader); err != nil {
		return err
	}

	dcontext.GetLogger(ctx).Infof("Challenge established with upstream : %s %s", remoteURL, r.cm)
	return nil
}

// proxiedRepository uses proxying blob and manifest services to serve content
// locally, or pulling it through from a remote and caching it locally if it doesn't
// already exist
type proxiedRepository struct {
	blobStore distribution.BlobStore
	manifests distribution.ManifestService
	name      reference.Named
	tags      distribution.TagService
}

func (pr *proxiedRepository) Manifests(ctx context.Context, options ...distribution.ManifestServiceOption) (distribution.ManifestService, error) {
	return pr.manifests, nil
}

func (pr *proxiedRepository) Blobs(ctx context.Context) distribution.BlobStore {
	return pr.blobStore
}

func (pr *proxiedRepository) Named() reference.Named {
	return pr.name
}

func (pr *proxiedRepository) Tags(ctx context.Context) distribution.TagService {
	return pr.tags
}
