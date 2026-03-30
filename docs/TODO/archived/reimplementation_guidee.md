
Nous allons reimplementer par la suite KunipaMail et KunipaLedger pour utiliser Rust + Tauri au lieu de Go + Wails.

Nous allons réimplémenter en premier kunipa-securedb pour évaluer Rust concrètement : petit scope, haute criticité, partageable avec KunipaLedger)

Nous devrions crééer une branche spéciale git/github pour y travailler, et définir un ADR. Meme si le scope est petit nous devrions prévoir le futur, meme si ce ne sera implémenté que plus tard:

Une solution de backups API long terme telle que envisagée dans docs/TODO/adr-strategie-backup-kunipa.md (Repository kunipachronos-internal).

Une fois la stratégie optimiséee nous pourrons installer Rust qui ne l'est pas encore et lancer la phase développement.

Une fois le code developpé, nous devrions relocaliser main dans par exemple main-go, ou archived-main-go pour en conserver pour le moment une copie, et ensuite merge main avec notre branche de reimplementation Rust quand tout sera pret et bien vérifié.
