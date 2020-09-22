package controllers

import (
	"context"
	"fmt"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	pxcv1 "github.com/Percona-Lab/k8s-vault-issuer/apis/pxc/v1"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
)

type Cluster struct {
	Name      string
	Namespace string
}

func (c Cluster) String() string {
	return c.Name + "." + c.Namespace
}

func (c Cluster) isCopyAllowed(allowedClusters string) bool {
	if allowedClusters == "*" {
		return true
	}
	currClusterStr := c.String()
	for _, v := range strings.Split(allowedClusters, ",") {
		if currClusterStr == v {
			return true
		}
	}
	return false
}

func (r *PerconaXtraDBClusterReconciler) processTransferVaultKeysAnnotation(currClusterCR *pxcv1.PerconaXtraDBCluster, clustersStr string) error {
	currCluster := Cluster{currClusterCR.Name, currClusterCR.Namespace}
	logger := r.Log.WithValues("curr cluster name", currCluster)

	clusters := strings.Split(clustersStr, ",")
	failedClusters := make([]string, 0)

	for _, v := range clusters {
		splittedName := strings.Split(v, ".")
		if len(splittedName) != 2 {
			logger.Error(nil, "invalid source cluster name, please use format clusterName.namespace", "src cluster", v)
			failedClusters = append(failedClusters, v)
			continue
		}

		srcCluster := Cluster{splittedName[0], splittedName[1]}

		err := r.processClusterKeysTransfer(currClusterCR, currCluster, srcCluster)
		if err != nil {
			r.Log.Error(err, "Can't process cluster", "scr cluster", srcCluster)
			failedClusters = append(failedClusters, v)
		}
	}

	if len(failedClusters) == 0 {
		return r.deleteAnnotation(currClusterCR, "percona.com/vault-transfer-keys")
	}

	return r.updateTransferKeysAnnotationClusters(currClusterCR, failedClusters)
}

func (r *PerconaXtraDBClusterReconciler) processClusterKeysTransfer(currentCR *pxcv1.PerconaXtraDBCluster, currCluster, srcCluster Cluster) error {
	srcClusterCR := &pxcv1.PerconaXtraDBCluster{}
	err := r.Client.Get(context.TODO(),
		types.NamespacedName{
			Namespace: srcCluster.Namespace,
			Name:      srcCluster.Name,
		}, srcClusterCR)
	if err != nil {
		return errors.Wrap(err, "get cluster definition")
	}

	values, ok := srcClusterCR.Annotations["percona.com/allow-transition-key-transfer"]
	if !ok {
		return errors.New("no percona.com/allow-transition-key-transfer annotation found")
	}

	if !currCluster.isCopyAllowed(values) {
		return errors.Errorf("transition key copy is now allowed")
	}

	return r.copyVaultTransitionKeys(currentCR, srcClusterCR)
}

func (r *PerconaXtraDBClusterReconciler) updateTransferKeysAnnotationClusters(o *pxcv1.PerconaXtraDBCluster, in []string) error {
	return r.Client.Patch(context.TODO(), o, client.RawPatch(types.JSONPatchType, []byte(fmt.Sprintf(
		`[{"op": "replace", "path": "/metadata/annotations/%s", "value": "%s"}]`,
		"percona.com~1vault-transfer-keys", strings.Join(in, ",")))))
}

func (r *PerconaXtraDBClusterReconciler) copyVaultTransitionKeys(from, to *pxcv1.PerconaXtraDBCluster) error {
	srcVaultConf, err := r.vaultConfFrom(from.Namespace, from.Spec.VaultSecretName)
	if err != nil {
		return errors.Wrapf(err, "get vault conf from namespace: %s, secretName: %s", from.Namespace, from.Spec.VaultSecretName)
	}

	targetVaultConf, err := r.vaultConfFrom(to.Namespace, to.Spec.VaultSecretName)
	if err != nil {
		return errors.Wrapf(err, "get vault conf from namespace: %s, secretName: %s", to.Namespace, to.Spec.VaultSecretName)
	}

	vaultSecretFrom := srcVaultConf.Config["secret_mount_point"]
	vaultSecretTo := targetVaultConf.Config["secret_mount_point"]

	r.Log.Info("Copying transition keys", "from", vaultSecretFrom, "to", vaultSecretTo)

	vaultRootConf, err := r.vaultConfFrom(r.Namespace, r.RootVaultSecretName)
	if err != nil {
		return errors.Wrap(err, "get root conf")
	}

	vaultClient, err := vaultClient(vaultRootConf)
	if err != nil {
		return errors.Wrap(err, "setup vault client")
	}

	logicalClient := vaultClient.Logical()
	secretList, err := logicalClient.List(vaultSecretFrom + "/backup/")
	if err != nil {
		return errors.Wrap(err, "list backup secretList")
	}

	if secretList == nil || secretList.Data == nil || secretList.Data["keys"] == nil {
		return errors.New("no transition keys found")
	}

	for _, backupUIDInterface := range secretList.Data["keys"].([]interface{}) {
		backupUID, ok := backupUIDInterface.(string)
		if !ok {
			r.Log.Error(nil, "Can't cast key to string", "key", backupUIDInterface)
			continue
		}

		secretData, err := logicalClient.Read(vaultSecretFrom + "/backup/" + backupUID)
		if err != nil {
			return errors.Wrap(err, "read secret data from vault")
		}

		_, err = logicalClient.Write(vaultSecretTo+"/backup/"+backupUID, secretData.Data)
		if err != nil {
			return errors.Wrap(err, "copy transition key")
		}
	}
	return nil
}
