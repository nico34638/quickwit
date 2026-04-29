# Jaeger v2 — Bugs identifiés et corrections

> Revue du code `quickwit-jaeger/src/v2.rs` — branche `metrics`, avril 2026.

---

## Bug 1 — `get_traces` ignore `start_time`/`end_time` de `GetTraceParams` (Critique)

**Fichier :** `quickwit-jaeger/src/v2.rs:157-158`

### Problème

La structure proto `GetTraceParams` expose des champs optionnels `start_time` et `end_time` permettant à l'appelant de borner la fenêtre de recherche pour un trace_id donné. Ces champs sont complètement ignorés : la fenêtre est toujours calculée depuis `now - lookback_period_secs`.

```rust
// actuel — ignore query_params.start_time / query_params.end_time
let end = OffsetDateTime::now_utc().unix_timestamp();
let search_window = (end - lookback_period_secs)..=end;
```

Conséquence : une trace dont tous les spans sont antérieurs à `now - lookback_period_secs` ne sera jamais retournée, même si `start_time` la désigne explicitement.

### Correction

Utiliser `start_time`/`end_time` quand ils sont présents, et ne fallback sur `lookback_period_secs` que si absents :

```rust
let end = query_params.end_time
    .map(|ts| ts.seconds)
    .unwrap_or_else(|| OffsetDateTime::now_utc().unix_timestamp());
let start = query_params.start_time
    .map(|ts| ts.seconds)
    .unwrap_or(end - lookback_period_secs);
let search_window = start..=end;
```

---

## Bug 2 — `find_trace_ids_impl` ignore `max_trace_duration_secs` (Critique)

**Fichier :** `quickwit-jaeger/src/v2.rs:310`

### Problème

Le paramètre est préfixé d'un underscore (`_max_trace_duration_secs`) — il est reçu mais jamais utilisé dans le corps de la fonction. La fonction `find_traces` l'utilise correctement pour calculer la fenêtre de la 2e requête, mais `find_trace_ids` (endpoint distinct) ne bénéficie pas de cette marge temporelle.

```rust
async fn find_trace_ids_impl(
    search_service: Arc<dyn SearchService>,
    _max_trace_duration_secs: i64,  // ignoré
    ...
```

Conséquence : `FindTraceIDs` peut retourner des trace_ids avec un `FoundTraceId.start`/`end` trop serré, ce qui amène l'appelant à faire un `GetTraces` avec une fenêtre insuffisante.

### Correction

Supprimer le préfixe `_` et utiliser le paramètre pour calculer les bornes du `FoundTraceId` retourné (élargir `start` et `end` de `max_trace_duration_secs`), ou passer le paramètre à `find_trace_ids_common` si une évolution future en a besoin.

---

## Bug 3 — `find_traces` : budget `max_fetch_spans` partagé entre toutes les traces (Critique)

**Fichier :** `quickwit-jaeger/src/v2.rs:224-250`

### Problème

`find_traces` effectue une **seule requête** pour fetcher les spans de toutes les traces matchées :

```rust
stream_otel_spans_impl(
    search_service,
    max_fetch_spans,   // budget global : 10 000 spans par défaut
    &trace_ids,        // toutes les traces en une fois
    search_window,
    ...
)
```

Quickwit retourne les `max_fetch_spans` premiers hits sans garantie de distribution équitable entre les traces. Si 20 traces sont demandées et que les premières ont beaucoup de spans, les dernières traces peuvent être partiellement ou totalement absentes du résultat.

Exemple : 20 traces × 600 spans = 12 000 spans nécessaires, mais `max_fetch_spans = 10 000` → 2 000 spans manquants répartis aléatoirement.

Par contraste, `get_traces` fait **une requête par trace** (boucle ligne 146), ce qui garantit que chaque trace dispose de son propre budget `max_fetch_spans`.

### Correction

Aligner `find_traces` sur `get_traces` : faire **N requêtes parallèles**, une par trace, chacune avec sa propre fenêtre temporelle dérivée du `span_timestamp` retourné par `FindTraceIdsCollector`.

Cela nécessite de modifier `find_trace_ids_common` (ou `collect_trace_ids`) pour retourner `Vec<(TraceId, i64)>` (trace_id + timestamp du span matché) au lieu de `(Vec<TraceId>, TimeIntervalSecs)`.

```
Avant :
  1 requête globale → max_fetch_spans partagés → traces incomplètes

Après :
  N requêtes parallèles (une par trace) → chaque trace a son propre budget
  → latence wall-clock similaire, traces complètes
```

Le nombre de traces est borné par `search_depth` (20 par défaut dans l'UI Jaeger), donc l'impact en charge reste contrôlé.

---

## Bug 4 — `service.name` potentiellement dupliqué dans les `resource_attributes` (Mineur)

**Fichier :** `quickwit-jaeger/src/v2.rs:494-503`

### Problème

`qw_spans_to_otel_traces_data` construit les attributs du `Resource` en ajoutant manuellement `service.name`, puis itère `first_span_attrs` (les `resource_attributes` du premier span) sans en avoir retiré `service.name` au préalable.

```rust
let mut resource_attrs = vec![OtelKeyValue {
    key: "service.name".to_string(),
    ...
}];
// first_span_attrs peut déjà contenir "service.name"
for (key, value) in first_span_attrs {
    resource_attrs.push(json_value_to_otel_kv(key, value));
}
```

La v1 retire explicitement `service.name` avant la conversion (`lib.rs:729` : `qw_span.resource_attributes.remove("service.name")`).

### Correction

Filtrer `service.name` lors de l'itération de `first_span_attrs` :

```rust
for (key, value) in first_span_attrs {
    if key != "service.name" {
        resource_attrs.push(json_value_to_otel_kv(key, value));
    }
}
```

---

## Bug 5 — Underflow possible dans `to_well_known_duration` (Mineur)

**Fichier :** `quickwit-jaeger/src/lib.rs:789`

### Problème

La soustraction entre deux `u64` peut provoquer un underflow (panic en debug, wrap en release) si `end_timestamp_nanos < start_timestamp_nanos` :

```rust
let duration_nanos = end_timestamp_nanos - start_timestamp_nanos;
```

Ce cas peut arriver avec des données corrompues ou des horloges désynchronisées entre services.

### Correction

```rust
let duration_nanos = end_timestamp_nanos.saturating_sub(start_timestamp_nanos);
```

---

## Bug 6 — Borne supérieure de timestamp supprimée à tort lors de la recherche dans un split (Corrigé)

**Fichier :** `quickwit-search/src/leaf.rs` — corrigé dans le commit `0e1cdee7b`

### Problème (historique)

`remove_redundant_timestamp_range` supprimait la borne supérieure d'un `RangeQuery` si `query_ts >= split.timestamp_end`. Or `split.timestamp_end` est la troncature à la seconde du timestamp maximum du split — le vrai maximum peut être jusqu'à `split.timestamp_end + 0.999s`. Des spans exactement sur la seconde de coupure pouvaient donc être inclus à tort.

Impact Jaeger : `FindTraceIdsCollector` pouvait rater des spans exactement à la borne de `end_timestamp`, causant la disparition de trace_ids du résultat.

### Correction apportée

Comparer avec `split_end + 1` (borne exclusive réelle) plutôt qu'avec `split_end` :

```rust
let split_end_exclusive = DateTime::from_timestamp_secs(split_end + 1);
if query_ts < split_end_exclusive {
    query_bound
} else {
    Bound::Unbounded
}
```

---

## Résumé

| # | Sévérité | Fichier | Problème | Statut |
|---|----------|---------|----------|--------|
| 1 | Critique | `v2.rs:157` | `GetTraceParams.start_time`/`end_time` ignorés | A corriger |
| 2 | Critique | `v2.rs:310` | `_max_trace_duration_secs` ignoré dans `find_trace_ids_impl` | A corriger |
| 3 | Critique | `v2.rs:224` | Budget `max_fetch_spans` partagé → traces incomplètes | A corriger |
| 4 | Mineur | `v2.rs:494` | `service.name` dupliqué dans `resource_attributes` | A corriger |
| 5 | Mineur | `lib.rs:789` | Underflow `u64` si `end < start` dans `to_well_known_duration` | A corriger |
| 6 | Mineur | `leaf.rs` | Borne supérieure timestamp supprimée à tort sur coupure de split | Corrigé (`0e1cdee7b`) |
