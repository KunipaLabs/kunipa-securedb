Oui — globalement, c’est un très bon plan. Il est cohérent, pragmatique, et surtout il respecte bien le fait que kunipa-securedb est un composant petit mais critique, donc la priorité doit être la fidélité sémantique à l’implémentation Go existante, pas une “rustification” excessive.

Les points les plus solides du plan :

rusqlite + bundled-sqlcipher par défaut : excellent choix pour réduire les surprises de build et garantir un comportement reproductible. Le feature flag system-sqlcipher est une bonne soupape pour les environnements packagés.
Single connection imposée structurellement : très bon. Pour un composant de sécurité/chiffrement SQLite, éviter les ambiguïtés de concurrence est plus important qu’optimiser le débit.
secrecy + zeroize : c’est exactement le genre d’amélioration que Rust permet par rapport à Go.
with_connection : bonne API pour empêcher les fuites de handle et garder le contrôle sur l’invariant “une connexion active”.
Port 1:1 des tests Go : probablement la partie la plus importante du plan. C’est ce qui transformera la migration en reimplementation fiable plutôt qu’en réécriture spéculative.

Là où je ferais attention, ce n’est pas sur la direction, mais sur quelques détails d’implémentation.

D’abord, le point le plus sensible : l’application et la vérification de la clé SQLCipher.
Le plan mentionne pragma_update("key", ...) ou appel FFI brut à sqlite3_key. Je recommanderais de choisir une seule stratégie et de la documenter explicitement. Idéalement :

si rusqlite + SQLCipher fonctionne proprement via PRAGMA key, rester là-dessus ;
ne passer au FFI brut que si vous avez une raison précise et testée.

Le risque, sinon, c’est d’introduire une zone grise où le comportement varie selon la version de SQLCipher ou la manière dont rusqlite encode le pragma.

Ensuite, je clarifierais la sémantique exacte des erreurs.
Votre mapping :

SQLITE_NOTADB -> WrongKey si clé fournie
sinon NotDatabase

est raisonnable, mais il faut être très précis sur les cas suivants :

fichier SQLite plaintext ouvert en mode chiffré ;
fichier SQLCipher avec mauvaise clé ;
fichier corrompu ;
fichier vide ou inexistant ;
base créée en mode Disabled puis rouverte en mode Required.

Ces cas ont souvent des symptômes SQLite très proches. Il faut que vos tests couvrent ces frontières, sinon vous risquez une régression subtile par rapport à Go.

Je pense aussi que verify_cipher_metadata(db) -> Result<String> est utile, mais je ne l’utiliserais pas comme critère principal de validité à l’ouverture. Le vrai test reste celui que vous avez prévu : une requête simple après application de la clé, par exemple lecture de sqlite_master. cipher_version est bon comme diagnostic, pas comme preuve suffisante.

Sur la structure Database, j’ai un léger doute sur :

Mutex<Option<Connection>>
Mutex<Option<SecretVec<u8>>>

Ça marche, mais vous avez deux mutex distincts pour des données qui participent au même invariant logique. J’envisagerais plutôt un seul mutex sur un state interne, par exemple :

Mutex<Inner { conn: Option<Connection>, key: Option<SecretVec<u8>> }>.

Ça évite des états intermédiaires incohérents entre clé et connexion, notamment pendant close(), rotate_key() ou Drop.

Autre point important : Drop ne doit pas être votre seule garantie de fermeture.
C’est bien d’avoir close(), mais je ferais en sorte que :

close() soit idempotente ;
toutes les méthodes après fermeture renvoient systématiquement Closed ;
Drop soit juste un filet de sécurité, pas un chemin logique principal.

Pour rotate_key, je rajouterais noir sur blanc dans le plan :

vérification que la DB est bien ouverte ;
PRAGMA rekey exécuté dans des conditions bien définies ;
mise à jour de la clé stockée uniquement si le rekey réussit ;
test de réouverture avec l’ancienne puis la nouvelle clé.

Ça paraît évident, mais c’est un des points de sécurité les plus délicats de tout le composant.

Sur les options, je trouve la surface API bonne. Je recommande juste de préciser la compatibilité entre options, par exemple :

read_only + create_if_missing doit probablement être invalide ;
:memory: avec WAL n’a pas forcément de sens ;
EncryptionMode::Disabled + clé fournie : est-ce erreur ou la clé est ignorée ?

Mieux vaut verrouiller ça tôt, sinon chaque caller interprétera différemment.

Sur la partie tests, 24 tests portés 1:1 est une excellente base, mais pour un composant comme celui-ci j’ajouterais au moins quelques tests Rust-spécifiques :

double close() ;
appel concurrent à with_connection() et close() ;
rotate_key() suivi de Drop ;
zéroïsation de la clé après close() si testable indirectement ;
comportement sur :memory: ;
comportement avec read_only.

Enfin, sur l’étape 8, je serais un peu plus conservateur :
ne supprimez pas immédiatement les sources Go tant que vous n’avez pas :

validé la parité de comportement,
branché le crate dans au moins un consumer réel,
et passé un mini audit interne.

Même si la branche est “Rust-only”, garder le Go un peu plus longtemps comme oracle de comparaison peut vous faire gagner du temps.

Mon avis synthétique :

Direction technique : très bonne
Niveau de risque : maîtrisé si la parité de tests est stricte
Points critiques : keying SQLCipher, mapping d’erreurs, invariants de fermeture/rotation

Les trois ajustements que je ferais au plan sont :

remplacer les deux Mutex<Option<...>> par un seul état interne sous mutex ;
trancher explicitement entre PRAGMA key et FFI brut pour la clé ;
détailler davantage les cas-limites d’erreurs et d’options incompatibles.