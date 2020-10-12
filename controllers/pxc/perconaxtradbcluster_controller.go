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
	"fmt"
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
)

// PerconaXtraDBClusterReconciler reconciles a PerconaXtraDBCluster object
type PerconaXtraDBClusterReconciler struct {
	client.Client
	Log                 logr.Logger
	Scheme              *runtime.Scheme
	Namespace           string
	RootVaultSecretName string
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

	if _, ok := o.Annotations["percona.com/issue-vault-token"]; ok {
		err = r.processVaultIssueAnnotation(o, log)
		if err != nil {
			return rr, errors.Wrap(err, "issue vault token")
		}
	}

	if val, ok := o.Annotations["percona.com/vault-transfer-keys"]; ok {
		log.Info("copying transition keys")
		err = r.processTransferVaultKeysAnnotation(o, val)
		if err != nil {
			return rr, errors.Wrap(err, "transfer vault keys")
		}
	}

	return rr, nil
}

func (r *PerconaXtraDBClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&pxcv1.PerconaXtraDBCluster{}).
		Complete(r)
}

func (r *PerconaXtraDBClusterReconciler) deleteAnnotation(o *pxcv1.PerconaXtraDBCluster, annotation string) error {
	annotation = strings.Replace(annotation, "/", "~1", -1)
	return r.Client.Patch(context.Background(), o, client.RawPatch(types.JSONPatchType, []byte(fmt.Sprintf("[{\"op\": \"remove\", \"path\": \"/metadata/annotations/%s\"}]", annotation))))
}
