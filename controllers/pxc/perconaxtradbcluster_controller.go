/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	pxcv1 "github.com/Percona-Lab/k8s-vault-issuer/apis/pxc/v1"
	api "github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PerconaXtraDBClusterReconciler reconciles a PerconaXtraDBCluster object
type PerconaXtraDBClusterReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=pxc.percona.com,resources=perconaxtradbclusters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pxc.percona.com,resources=perconaxtradbclusters/status,verbs=get;update;patch

func (r *PerconaXtraDBClusterReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("perconaxtradbcluster", req.NamespacedName)

	rr := reconcile.Result{
		RequeueAfter: time.Second * 5,
	}

	o := &pxcv1.PerconaXtraDBCluster{}
	err := r.Client.Get(context.TODO(), req.NamespacedName, o)
	if err != nil {
		return rr, err
	}

	if _, ok := o.Annotations["percona.com/issue-vault-token"]; !ok {
		return rr, nil
	}

	log.Info("found annotation")

	opNs, err := operatorNamespace()
	if err != nil {
		return rr, errors.Wrap(err, "get operator namespace")
	}

	newSecretObj := corev1.Secret{}
	err = r.Client.Get(context.TODO(),
		types.NamespacedName{
			Namespace: o.Namespace,
			Name:      o.Spec.VaultSecretName,
		},
		&newSecretObj,
	)
	if !apierrors.IsNotFound(err) {
		return rr, err
	}
	if err == nil {
		log.Info("issued secret was found, delete annotaton")
		err = r.deleteAnnotation(o)
		return rr, err
	}

	rootSecretName, err := rootSecretName()
	if err != nil {
		return rr, err
	}

	rootSecretObj := corev1.Secret{}
	err = r.Client.Get(context.TODO(),
		types.NamespacedName{
			Namespace: opNs,
			Name:      rootSecretName,
		},
		&rootSecretObj,
	)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("root secret was not found")
			return rr, nil
		}
		return rr, err
	}

	err = r.IssueVaultToken(rootSecretObj, o.Spec.VaultSecretName, o.Namespace)
	if err != nil {
		return rr, err
	}

	log.Info("token was issued, delete annotation")

	return rr, r.deleteAnnotation(o)
}

func (r *PerconaXtraDBClusterReconciler) deleteAnnotation(o *pxcv1.PerconaXtraDBCluster) error {
	return r.Client.Patch(context.Background(), o, client.RawPatch(types.JSONPatchType, []byte("[{\"op\": \"remove\", \"path\": \"/metadata/annotations/percona.com~1issue-vault-token\"}]")))
}

func rootSecretName() (string, error) {
	if s, ok := os.LookupEnv("VAULT_SECRET_NAME"); ok {
		return s, nil
	}
	return "", errors.New("VAULT_SECRET_NAME env is not set")
}

func (r *PerconaXtraDBClusterReconciler) IssueVaultToken(rootVaultSercet corev1.Secret, newSecretName string, customerNamespace string) error {
	data := string(rootVaultSercet.Data["keyring_vault.conf"])
	fields := strings.Split(data, "\n")
	conf := make(map[string]string)
	for _, f := range fields {
		kv := strings.Split(f, "=")
		conf[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}

	newData := make(map[string][]byte)

	tr := &http.Transport{}
	if ca, ok := rootVaultSercet.Data["ca.cert"]; ok {
		newData["ca.cert"] = ca

		certPool, err := x509.SystemCertPool()
		if err != nil {
			return errors.Wrap(err, "failed to get system cert pool")
		}

		ok := certPool.AppendCertsFromPEM(ca)
		if !ok {
			return errors.New("failed to append cert")
		}

		tr.TLSClientConfig = &tls.Config{
			RootCAs: certPool,
		}
	}

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}
	cli, err := api.NewClient(&api.Config{
		HttpClient: httpClient,
		Address:    conf["vault_url"],
	})
	if err != nil {
		return errors.Wrap(err, "failed to create vault client")
	}

	cli.SetToken(conf["token"])
	path := fmt.Sprintf("%s/%s/%s", conf["secret_mount_point"], customerNamespace, newSecretName)
	policy := fmt.Sprintf(`
path "%s"
{
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "%s/*"
{
  capabilities = ["create", "read", "update", "delete", "list"]
}
`, path, path)

	policyName := fmt.Sprintf("%s-%s", customerNamespace, newSecretName)
	err = cli.Sys().PutPolicy(policyName, policy)
	if err != nil {
		return errors.Wrap(err, "failed to put policy")
	}

	sec, err := cli.Auth().Token().Create(&api.TokenCreateRequest{
		Policies: []string{policyName},
	})
	if err != nil {
		return errors.Wrap(err, "failed to create token")
	}

	token := sec.Auth.ClientToken
	newData["keyring_vault.conf"] = []byte(
		fmt.Sprintf(`
token = %s
vault_url = %s
secret_mount_point = %s
vault_ca = %s`,
			token,
			conf["vault_url"],
			path,
			conf["vault_ca"],
		))

	secretObj := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      newSecretName,
			Namespace: customerNamespace,
		},
		Data: newData,
		Type: corev1.SecretTypeOpaque,
	}

	err = r.Client.Create(context.TODO(), &secretObj)
	if err != nil {
		return errors.Wrap(err, "create token secret")
	}

	return nil
}

func (r *PerconaXtraDBClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&pxcv1.PerconaXtraDBCluster{}).
		Complete(r)
}

func operatorNamespace() (string, error) {
	nsBytes, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(nsBytes)), nil
}
