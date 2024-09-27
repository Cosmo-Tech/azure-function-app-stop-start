import os
import time
import logging
import yaml
import base64
import hvac
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.mgmt.containerservice import ContainerServiceClient
from kubernetes import client, config
from kubernetes.config.kube_config import KubeConfigLoader
from shared.holiday_check import is_holiday

logging.basicConfig(level=logging.INFO)

def main(startakstimer: func.TimerRequest) -> None:
    if is_holiday():
        logging.info("Aujourd'hui est un jour férié. Opération annulée.")
        return

    # Configuration
    subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
    resource_group = os.environ["AKS_RESOURCE_GROUP"]
    cluster_name = os.environ["AKS_CLUSTER_NAME"]
    vault_namespace = os.environ.get("VAULT_NAMESPACE", "vault")
    vault_address = os.environ.get("VAULT_ADDR", "http://kubejlou-dns-s7pfhzf2.hcp.francecentral.azmk8s.io")

    # Initialisation des clients Azure
    azure_credential = DefaultAzureCredential()
    aks_client = ContainerServiceClient(azure_credential, subscription_id)

    # Démarrage et vérification du cluster AKS
    start_and_verify_aks_cluster(aks_client, resource_group, cluster_name)

    # Obtention des informations d'identification du cluster
    kubeconfig = get_aks_admin_credentials(aks_client, resource_group, cluster_name)

    # Configuration du client Kubernetes
    api_client = get_kubernetes_api_client(kubeconfig)
    k8s_client = client.CoreV1Api(api_client)

    # Récupération des unseal_keys depuis le secret Kubernetes
    unseal_keys = get_unseal_keys_from_secret(k8s_client, vault_namespace)

    # Déverrouillage de Vault via HVAC
    client_vault = hvac.Client(url=vault_address)
    check_and_unseal_vault_hvac(client_vault, unseal_keys)

    logging.info("Opération terminée avec succès.")

def start_and_verify_aks_cluster(aks_client, resource_group, cluster_name):
    logging.info(f"Vérification de l'état du cluster AKS {cluster_name}")
    try:
        # Vérifier l'état actuel du cluster
        cluster = aks_client.managed_clusters.get(resource_group, cluster_name)
        if cluster.power_state.code != "Running":
            logging.info(f"Démarrage du cluster AKS {cluster_name}")
            aks_client.managed_clusters.begin_start(resource_group, cluster_name).result()
            logging.info(f"Le cluster AKS {cluster_name} est démarré")
        else:
            logging.info(f"Le cluster AKS {cluster_name} est déjà en cours d'exécution")
    except Exception as e:
        logging.error(f"Erreur lors du démarrage du cluster AKS : {e}")
        raise

def get_aks_admin_credentials(aks_client, resource_group, cluster_name):
    logging.info("Récupération des informations d'identification administrateur du cluster AKS via SDK Azure")
    try:
        result = aks_client.managed_clusters.list_cluster_admin_credentials(resource_group, cluster_name)
        kubeconfig_str = result.kubeconfigs[0].value.decode("utf-8")
        logging.info("Informations d'identification administrateur du cluster AKS récupérées avec succès")
        return kubeconfig_str
    except Exception as e:
        logging.error(f"Erreur lors de la récupération des informations d'identification du cluster AKS : {e}")
        raise

def get_kubernetes_api_client(kubeconfig_str):
    # Charger la configuration Kubernetes depuis le kubeconfig obtenu
    cfg_dict = yaml.safe_load(kubeconfig_str)
    loader = KubeConfigLoader(cfg_dict)
    configuration = client.Configuration()
    loader.load_and_set(configuration)
    api_client = client.ApiClient(configuration)
    logging.info("Client Kubernetes configuré avec succès")
    return api_client

def get_unseal_keys_from_secret(k8s_client, namespace):
    logging.info("Récupération des unseal_keys depuis le secret Kubernetes")
    try:
        secret = k8s_client.read_namespaced_secret("unseal-keys", namespace)
        unseal_keys_encoded = secret.data.get("UNSEAL_KEYS")
        if not unseal_keys_encoded:
            raise ValueError("Le secret 'unseal-keys' ne contient pas de champ 'UNSEAL_KEYS'")
        unseal_keys_str = base64.b64decode(unseal_keys_encoded).decode("utf-8")
        unseal_keys_list = unseal_keys_str.split(',')
        logging.info("Unseal keys récupérées avec succès depuis le secret Kubernetes")
        return unseal_keys_list
    except Exception as e:
        logging.error(f"Erreur lors de la récupération des unseal keys : {e}")
        raise

def check_and_unseal_vault_hvac(client_vault, unseal_keys):
    logging.info("Vérification de l'état de Vault via HVAC")
    try:
        # Vérification du statut de Vault
        seal_status = client_vault.sys.read_seal_status()
        if seal_status['sealed']:
            logging.info("Vault est scellé. Déverrouillage en cours...")
            for key in unseal_keys:
                client_vault.sys.submit_unseal_key(key)
                seal_status = client_vault.sys.read_seal_status()
                if not seal_status['sealed']:
                    logging.info("Vault est déverrouillé avec succès")
                    break
        else:
            logging.info("Vault est déjà déverrouillé")
    except Exception as e:
        logging.error(f"Erreur lors du déverrouillage de Vault via HVAC : {e}")
        raise
