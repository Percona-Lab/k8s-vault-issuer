package controllers

import (
	"context"
	"fmt"
	"strings"

	pxcv1 "github.com/Percona-Lab/k8s-vault-issuer/apis/pxc/v1"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
)

func (r *PerconaXtraDBClusterReconciler) processTransferVaultKeys(o *pxcv1.PerconaXtraDBCluster, clusters []string) error {
	currCluster := o.ClusterName + "." + r.Namespace
	for _, v := range clusters {
		splittedName := strings.Split(v, ".")
		clusterName, clusterNamespace := splittedName[0], splittedName[1]

		spec := &pxcv1.PerconaXtraDBCluster{}
		err := r.Client.Get(context.TODO(),
			types.NamespacedName{
				Namespace: clusterNamespace,
				Name:      clusterName,
			}, spec)
		if err != nil {
			return errors.Wrap(err, "get cluster spec from namespace "+v)
		}

		values, ok := spec.Annotations["percona.com/allow-transition-key-transfer"]
		if !ok {
			return fmt.Errorf("No percona.com/allow-transition-key-transfer annotation found at cluster %s", v)
		}

		allowed := false
		for _, allowedClusters := range strings.Split(values, ",") {
			if allowedClusters == currCluster {
				allowed = true
				break
			}
		}

		if !allowed {
			return fmt.Errorf("Cluster %s is not allowing copying keys for cluster %s ", v, currCluster)
		}

		if err := r.transferTransitionKeys(v, o.Namespace); err != nil {
			return errors.Wrapf(err, "transfer transition key from:%s to:%s", v, o.Namespace)
		}
	}
	return nil
}

func (r *PerconaXtraDBClusterReconciler) transferTransitionKeys(secretFrom, toNS string) error {
	vaultConf, err := r.vaultRootConf()
	if err != nil {
		return errors.Wrap(err, "get root conf")
	}

	vaultClient, err := vaultClient(vaultConf)
	if err != nil {
		return errors.Wrap(err, "setup vault client")
	}
	logicalClient := vaultClient.Logical()
	secrets, err := logicalClient.List(secretFrom + "/backup/")
	if err != nil {
		return errors.Wrap(err, "list backup secrets")
	}
	result := make(map[string]string, 0)
	for backupUID := range secrets.Data {
		secretData, err := logicalClient.Read(secretFrom + "/backup/" + backupUID)
		if err != nil {
			return errors.Wrap(err, "read secret data from vault")
		}
		result[backupUID] = secretData.Data["transition_key"].(string)
	}

}
