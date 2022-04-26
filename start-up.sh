nohup /opt/keycloak/bin/kc.sh start-dev
/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080/ --realm master --user admin --password admin
/opt/keycloak/bin/kcadm.sh create partialImport -r admin -s ifResourceExists=FAIL -o -f /data/import/realm-export.json
