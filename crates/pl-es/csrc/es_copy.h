/* Internal: es_message_t -> pl_raw_event_t copy, shared by the handler and the self-test. */
#ifndef PL_ES_COPY_H
#define PL_ES_COPY_H

#include <EndpointSecurity/EndpointSecurity.h>

#include "rawevent.h"

/* Porchlight type for an ES event type, or PL_EV_NONE if not subscribed in this milestone. */
uint32_t pl_es_classify(es_event_type_t type);
/* Copies everything Porchlight keeps. No allocation, no locks, no I/O (C5). */
void pl_es_copy(const es_message_t *msg, uint32_t pl_type, pl_raw_event_t *out);

#endif
