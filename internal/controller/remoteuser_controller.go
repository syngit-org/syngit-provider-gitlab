/*
Copyright 2024.

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

package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"maps"
	"net/http"

	syngit "github.com/syngit-org/syngit/pkg/api/v1beta2"
	syngitutils "github.com/syngit-org/syngit/pkg/utils"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// RemoteUserReconciler reconciles a RemoteUser object
type RemoteUserReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

type RemoteUserChecker struct {
	remoteUser syngit.RemoteUser
}

// +kubebuilder:rbac:groups=syngit.io,resources=remoteusers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=syngit.io,resources=remoteusers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=syngit.io,resources=remoteusers/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch

const (
	authAnnotation         = "gitlab.syngit.io/auth.test"
	skipInsecureAnnotation = "gitlab.syngit.io/auth.insecure-skip-tls-verify"
	caBundleRefAnnotation  = "gitlab.syngit.io/auth.ca-bundle-secret-ref-name"
)

func (r *RemoteUserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	// Get the RemoteUser Object
	var remoteUser syngit.RemoteUser
	if err := r.Get(ctx, req.NamespacedName, &remoteUser); err != nil {
		// does not exists -> deleted
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Log.Info("Reconcile request",
		"resource", "remoteuser",
		"namespace", remoteUser.Namespace,
		"name", remoteUser.Name,
	)

	remoteUserChecker := RemoteUserChecker{remoteUser: *remoteUser.DeepCopy()}
	r.testConnection(&remoteUserChecker)

	remoteUser.Status.Conditions = remoteUserChecker.remoteUser.Status.Conditions
	_ = r.updateStatus(ctx, req, remoteUserChecker.remoteUser.Status, 2)

	return ctrl.Result{}, nil
}

func (r *RemoteUserReconciler) getCABundle(remoteUser syngit.RemoteUser) ([]byte, error) {
	var caBundle []byte
	if caBundleRefName := remoteUser.Annotations[caBundleRefAnnotation]; caBundleRefName != "" {
		var caErr error
		caBundleRu, caErr := syngitutils.FindCABundle(r.Client, remoteUser.Namespace, caBundleRefName)
		if caErr != nil {
			return nil, caErr
		}
		if caBundleRu != nil {
			caBundle = caBundleRu
		}

		return caBundle, nil
	}
	return syngitutils.FindGlobalCABundle(r.Client, remoteUser.Spec.GitBaseDomainFQDN)
}

func (r RemoteUserReconciler) testConnection(ruc *RemoteUserChecker) {
	conditions := ruc.remoteUser.Status.DeepCopy().Conditions

	if ruc.remoteUser.Annotations[authAnnotation] != "true" {
		ruc.remoteUser.Status.Conditions = syngitutils.TypeBasedConditionRemover(conditions, "Authenticated")
	} else {
		errorCondition := metav1.Condition{
			Type:               "Authenticated",
			Status:             metav1.ConditionFalse,
			Reason:             "AuthenticationFailed",
			LastTransitionTime: metav1.Now(),
		}

		// Get connection credentials
		var secret corev1.Secret
		namespacedNameSecret := types.NamespacedName{Namespace: ruc.remoteUser.Namespace, Name: ruc.remoteUser.Spec.SecretRef.Name}
		if err := r.Get(context.Background(), namespacedNameSecret, &secret); err != nil {
			secret = corev1.Secret{}
		}

		tlsConfig := &tls.Config{}

		// Get the CA bundle if exists
		caBundle, caErr := r.getCABundle(ruc.remoteUser)

		if caBundle != nil {
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caBundle) {
				caCertPoolErrorMessage := "Failed to append CA bundle"
				errorCondition.Message = caCertPoolErrorMessage
				ruc.remoteUser.Status.ConnexionStatus.Status = ""
				ruc.remoteUser.Status.ConnexionStatus.Details = caCertPoolErrorMessage
				ruc.remoteUser.Status.Conditions = syngitutils.TypeBasedConditionUpdater(conditions, errorCondition)
				return
			}
			tlsConfig.RootCAs = caCertPool
		}

		// Check if insecure skip tls verify
		if ruc.remoteUser.Annotations[skipInsecureAnnotation] == "true" {
			tlsConfig.InsecureSkipVerify = true
		}

		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}

		if len(secret.Data) != 0 {

			gitlabClient, gitlabClientErr := gitlab.NewClient(string(secret.Data["password"]),
				gitlab.WithBaseURL(fmt.Sprintf("https://%s", ruc.remoteUser.Spec.GitBaseDomainFQDN)),
				gitlab.WithHTTPClient(httpClient),
			)
			if gitlabClientErr != nil {
				if caErr != nil {
					errorCondition.Message = caErr.Error()
					ruc.remoteUser.Status.ConnexionStatus.Status = ""
					ruc.remoteUser.Status.ConnexionStatus.Details = caErr.Error()
					ruc.remoteUser.Status.Conditions = syngitutils.TypeBasedConditionUpdater(conditions, errorCondition)
					return
				} else {
					errorCondition.Message = gitlabClientErr.Error()
					ruc.remoteUser.Status.ConnexionStatus.Status = ""
					ruc.remoteUser.Status.ConnexionStatus.Details = gitlabClientErr.Error()
					ruc.remoteUser.Status.Conditions = syngitutils.TypeBasedConditionUpdater(conditions, errorCondition)
					return
				}
			}

			user, _, userErr := gitlabClient.Users.CurrentUser()
			if userErr != nil {
				errorCondition.Message = userErr.Error()
				ruc.remoteUser.Status.ConnexionStatus.Status = ""
				ruc.remoteUser.Status.ConnexionStatus.Details = userErr.Error()
				ruc.remoteUser.Status.Conditions = syngitutils.TypeBasedConditionUpdater(conditions, errorCondition)
				return
			}
			condition := metav1.Condition{
				Type:               "Authenticated",
				Status:             metav1.ConditionTrue,
				Reason:             "AuthenticationSucceded",
				Message:            fmt.Sprintf("Authentication was successful with the user %s", user.Username),
				LastTransitionTime: metav1.Now(),
			}
			ruc.remoteUser.Status.ConnexionStatus.Details = ""
			ruc.remoteUser.Status.ConnexionStatus.Status = syngit.GitConnected
			ruc.remoteUser.Status.Conditions = syngitutils.TypeBasedConditionUpdater(conditions, condition)
		}
	}
}

func (r *RemoteUserReconciler) updateStatus(ctx context.Context, req ctrl.Request, status syngit.RemoteUserStatus, retryNumber int) error {
	var remoteUser syngit.RemoteUser
	if err := r.Get(ctx, req.NamespacedName, &remoteUser); err != nil {
		return err
	}

	remoteUser.Status.ConnexionStatus = status.ConnexionStatus
	remoteUser.Status.Conditions = status.Conditions
	if err := r.Status().Update(ctx, &remoteUser); err != nil {
		if retryNumber > 0 {
			return r.updateStatus(ctx, req, status, retryNumber-1)
		}
		return err
	}
	return nil
}

func (r *RemoteUserReconciler) findObjectsForSecret(ctx context.Context, secret client.Object) []reconcile.Request {
	attachedRemoteUsers := &syngit.RemoteUserList{}
	listOps := &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(syngit.SecretRefField, secret.GetName()),
		Namespace:     secret.GetNamespace(),
	}
	err := r.List(ctx, attachedRemoteUsers, listOps)
	if err != nil {
		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, len(attachedRemoteUsers.Items))
	for i, item := range attachedRemoteUsers.Items {
		requests[i] = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      item.GetName(),
				Namespace: item.GetNamespace(),
			},
		}
	}
	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *RemoteUserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &syngit.RemoteUser{}, syngit.SecretRefField, func(rawObj client.Object) []string {
		// Extract the Secret name from the RemoteUser Spec, if one is provided
		remoteUser := rawObj.(*syngit.RemoteUser)
		if remoteUser.Spec.SecretRef.Name == "" {
			return nil
		}
		return []string{remoteUser.Spec.SecretRef.Name}
	}); err != nil {
		return err
	}

	p := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldObject, _ := e.ObjectOld.(*syngit.RemoteUser)
			newObject, _ := e.ObjectNew.(*syngit.RemoteUser)

			if newObject != nil {
				if !maps.Equal(oldObject.DeepCopy().Labels, newObject.DeepCopy().Labels) {
					return true
				}
				if !maps.Equal(oldObject.DeepCopy().Annotations, newObject.DeepCopy().Annotations) {
					return true
				}
				if oldObject.DeepCopy().Spec != newObject.Spec {
					return true
				}
			}
			return false
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&syngit.RemoteUser{}).
		Named("remoteuser").
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findObjectsForSecret),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		WithEventFilter(p).
		Complete(r)
}
