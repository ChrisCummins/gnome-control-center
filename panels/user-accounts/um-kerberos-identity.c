/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Author: Ray Strode
 */

#include "config.h"

#include "um-identity.h"
#include "um-kerberos-identity.h"
#include "um-alarm.h"

#include <string.h>
#include <glib/gi18n.h>
#include <gio/gio.h>

struct _UmKerberosIdentityPrivate
{
        krb5_context    kerberos_context;
        krb5_ccache     credentials_cache;

        char           *identifier;
        char           *cached_principal_name;
        char           *cached_realm_name;
        UmAlarm        *expiration_alarm;
        GCancellable   *expiration_alarm_cancellable;
        krb5_timestamp  expiration_time;

        GRecMutex       updates_lock;
};

typedef enum
{
        VERIFICATION_LEVEL_UNVERIFIED,
        VERIFICATION_LEVEL_ERROR,
        VERIFICATION_LEVEL_EXISTS,
        VERIFICATION_LEVEL_SIGNED_IN
} VerificationLevel;

enum {
        EXPIRED,
        UNEXPIRED,
        NUMBER_OF_SIGNALS,
};

static guint signals[NUMBER_OF_SIGNALS] = { 0 };

static void identity_interface_init (UmIdentityInterface *interface);
static void initable_interface_init (GInitableIface *interface);
static void set_expiration_alarm    (UmKerberosIdentity *self);

G_DEFINE_TYPE_WITH_CODE (UmKerberosIdentity,
                         um_kerberos_identity,
                         G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (UM_TYPE_IDENTITY,
                                                identity_interface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                initable_interface_init));

static void
um_kerberos_identity_dispose (GObject *object)
{
        UmKerberosIdentity *self = UM_KERBEROS_IDENTITY (object);

        if (self->priv->expiration_alarm_cancellable != NULL) {
                if (!g_cancellable_is_cancelled (self->priv->expiration_alarm_cancellable)) {
                        g_cancellable_cancel (self->priv->expiration_alarm_cancellable);
                }
                g_object_unref (self->priv->expiration_alarm_cancellable);
                self->priv->expiration_alarm_cancellable = NULL;
        }

        if (self->priv->expiration_alarm != NULL) {
                g_object_unref (self->priv->expiration_alarm);
                self->priv->expiration_alarm = NULL;
        }

}

static void
um_kerberos_identity_finalize (GObject *object)
{
        UmKerberosIdentity *self = UM_KERBEROS_IDENTITY (object);

        g_free (self->priv->identifier);
        self->priv->identifier = NULL;

        if (self->priv->credentials_cache != NULL) {
                krb5_cc_close (self->priv->kerberos_context, self->priv->credentials_cache);
        }
        G_OBJECT_CLASS (um_kerberos_identity_parent_class)->finalize (object);
}

static void
um_kerberos_identity_class_init (UmKerberosIdentityClass *klass)
{
        GObjectClass *object_class;

        object_class = G_OBJECT_CLASS (klass);

        object_class->dispose = um_kerberos_identity_dispose;
        object_class->finalize = um_kerberos_identity_finalize;

        g_type_class_add_private (klass, sizeof (UmKerberosIdentityPrivate));

        signals[EXPIRED] = g_signal_new ("expired",
                                         G_TYPE_FROM_CLASS (klass),
                                         G_SIGNAL_RUN_LAST,
                                         0,
                                         NULL, NULL, NULL,
                                         G_TYPE_NONE, 0);
        signals[UNEXPIRED] = g_signal_new ("unexpired",
                                           G_TYPE_FROM_CLASS (klass),
                                           G_SIGNAL_RUN_LAST,
                                           0,
                                           NULL, NULL, NULL,
                                           G_TYPE_NONE, 0);
}

static void
um_kerberos_identity_init (UmKerberosIdentity *self)
{
        self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
                                                  UM_TYPE_KERBEROS_IDENTITY,
                                                  UmKerberosIdentityPrivate);

        g_rec_mutex_init (&self->priv->updates_lock);

        self->priv->expiration_alarm = um_alarm_new ();
}

static char *
get_principal_name (UmKerberosIdentity *self,
                    gboolean            for_display)
{
        krb5_principal principal;
        krb5_error_code error_code;
        char *unparsed_name;
        char *principal_name;
        int flags;

        if (self->priv->credentials_cache == NULL) {
                return NULL;
        }

        error_code = krb5_cc_get_principal (self->priv->kerberos_context,
                                            self->priv->credentials_cache,
                                            &principal);

        if (error_code != 0) {
                const char *error_message;
                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);
                g_warning ("UmKerberosIdentity: Error looking up principal identity in credential cache: %s", error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
                return NULL;
        }

        if (for_display) {
                flags = KRB5_PRINCIPAL_UNPARSE_DISPLAY;
        } else {
                flags = 0;
        }

        error_code = krb5_unparse_name_flags (self->priv->kerberos_context,
                                              principal,
                                              flags,
                                              &unparsed_name);

        if (error_code != 0) {
                const char *error_message;

                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);
                g_warning ("UmKerberosIdentity: Error parsing principal identity name: %s", error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
                return NULL;
        }

        principal_name = g_strdup (unparsed_name);
        krb5_free_unparsed_name (self->priv->kerberos_context, unparsed_name);

        return principal_name;
}

char *
um_kerberos_identity_get_principal_name (UmKerberosIdentity *self)
{
        char *principal_name;

        um_kerberos_identity_block_updates (self);
        if (self->priv->cached_principal_name == NULL) {
                self->priv->cached_principal_name = get_principal_name (self, TRUE);
        }
        principal_name = g_strdup (self->priv->cached_principal_name);
        um_kerberos_identity_stop_blocking_updates (self);

        return principal_name;
}

static char *
get_realm_name (UmKerberosIdentity *self)
{
        krb5_principal principal;
        krb5_error_code error_code;
        krb5_data *realm;
        char *realm_name;

        if (self->priv->credentials_cache == NULL) {
                return NULL;
        }

        error_code = krb5_cc_get_principal (self->priv->kerberos_context,
                                            self->priv->credentials_cache,
                                            &principal);

        if (error_code != 0) {
                const char *error_message;
                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);
                g_warning ("UmKerberosIdentity: Error looking up principal identity in credential cache: %s", error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
                um_kerberos_identity_stop_blocking_updates (self);
                return NULL;
        }

        realm = krb5_princ_realm (self->priv->kerberos_context,
                                  principal);
        realm_name = g_strndup (realm->data, realm->length);
        krb5_free_principal (self->priv->kerberos_context, principal);

        um_kerberos_identity_stop_blocking_updates (self);

        return realm_name;
}

char *
um_kerberos_identity_get_realm_name (UmKerberosIdentity *self)
{
        char *realm_name;

        um_kerberos_identity_block_updates (self);
        if (self->priv->cached_realm_name == NULL) {
                self->priv->cached_realm_name = get_realm_name (self);
        }

        realm_name = g_strdup (self->priv->cached_realm_name);
        um_kerberos_identity_stop_blocking_updates (self);

        return realm_name;
}

static const char *
um_kerberos_identity_get_identifier (UmIdentity *identity)
{
        UmKerberosIdentity *self = UM_KERBEROS_IDENTITY (identity);

        if (self->priv->identifier == NULL) {
                self->priv->identifier = get_principal_name (self, FALSE);
        }

        return self->priv->identifier;
}

static gboolean
credentials_validate_existence (UmKerberosIdentity *self,
                                krb5_principal      principal,
                                krb5_creds         *credentials)
{
        /* Checks if default principal associated with the cache has a valid
         * ticket granting ticket in the passed in credentials
         */

        if (krb5_is_config_principal (self->priv->kerberos_context,
                                      credentials->server)) {
                return FALSE;
        }

        /* looking for the krbtgt / REALM pair, so it should be exactly 2 items */
        if (krb5_princ_size (self->priv->kerberos_context,
                             credentials->server) != 2) {
                return FALSE;
        }

        if (!krb5_realm_compare (self->priv->kerberos_context,
                                 credentials->server,
                                 principal)) {
                /* credentials are from some other realm */
                return FALSE;
        }

        if (strncmp (credentials->server->data[0].data,
                     KRB5_TGS_NAME,
                     credentials->server->data[0].length) != 0) {
                /* credentials aren't for ticket granting */
                return FALSE;
        }

        if (credentials->server->data[1].length != principal->realm.length ||
            memcmp (credentials->server->data[1].data,
                    principal->realm.data,
                    principal->realm.length) != 0) {
                /* credentials are for some other realm */
                return FALSE;
        }

        return TRUE;
}

static krb5_timestamp
get_current_time (UmKerberosIdentity *self)
{
        krb5_timestamp  current_time;
        krb5_error_code error_code;

        error_code = krb5_timeofday (self->priv->kerberos_context,
                                     &current_time);

        if (error_code != 0) {
                const char *error_message;

                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);
                g_warning ("UmKerberosIdentity: Error getting current time: %s", error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
                return 0;
        }

        return current_time;
}

static gboolean
credentials_are_expired (UmKerberosIdentity *self,
                         krb5_creds         *credentials)
{
        krb5_timestamp  current_time;

        current_time = get_current_time (self);

        self->priv->expiration_time = MAX (credentials->times.endtime,
                                           self->priv->expiration_time);

        if (credentials->times.endtime <= current_time) {
                return TRUE;
        }

        return FALSE;
}

static VerificationLevel
verify_identity (UmKerberosIdentity  *self,
                 GError             **error)
{
        krb5_principal principal;
        const char *error_message;
        krb5_cc_cursor cursor;
        krb5_creds credentials;
        krb5_error_code error_code;
        VerificationLevel verification_level;

        if (self->priv->credentials_cache == NULL) {
                return VERIFICATION_LEVEL_UNVERIFIED;
        }

        error_code = krb5_cc_get_principal (self->priv->kerberos_context,
                                            self->priv->credentials_cache,
                                            &principal);

        if (error_code != 0) {
                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);

                if (error_code == KRB5_CC_END) {
                        return VERIFICATION_LEVEL_UNVERIFIED;
                }

                g_set_error (error,
                             UM_IDENTITY_ERROR,
                             UM_IDENTITY_ERROR_VERIFYING,
                             _("Could not find identity in credential cache: %s"),
                             error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);

                return VERIFICATION_LEVEL_ERROR;
        }

        error_code = krb5_cc_start_seq_get (self->priv->kerberos_context,
                                            self->priv->credentials_cache,
                                            &cursor);
        if (error_code != 0) {
                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);
                g_set_error (error,
                             UM_IDENTITY_ERROR,
                             UM_IDENTITY_ERROR_VERIFYING,
                             _("Could not find identity credentials in cache: %s"),
                             error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);

                verification_level = VERIFICATION_LEVEL_ERROR;
                goto out;
        }

        verification_level = VERIFICATION_LEVEL_UNVERIFIED;

        error_code = krb5_cc_next_cred (self->priv->kerberos_context,
                                        self->priv->credentials_cache,
                                        &cursor,
                                        &credentials);

        while (error_code == 0) {
                if (credentials_validate_existence (self, principal, &credentials)) {
                        if (!credentials_are_expired (self, &credentials)) {
                                verification_level = VERIFICATION_LEVEL_SIGNED_IN;
                        } else {
                                verification_level = VERIFICATION_LEVEL_EXISTS;
                        }
                }

                error_code = krb5_cc_next_cred (self->priv->kerberos_context,
                                                self->priv->credentials_cache,
                                                &cursor,
                                                &credentials);
        }

        if (error_code != KRB5_CC_END) {
                verification_level = VERIFICATION_LEVEL_ERROR;

                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);
                g_set_error (error,
                             UM_IDENTITY_ERROR,
                             UM_IDENTITY_ERROR_VERIFYING,
                             _("Could not sift through identity credentials in cache: %s"),
                             error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
        }

        error_code = krb5_cc_end_seq_get (self->priv->kerberos_context,
                                          self->priv->credentials_cache,
                                          &cursor);

        if (error_code != 0) {
                verification_level = VERIFICATION_LEVEL_ERROR;

                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);
                g_set_error (error,
                             UM_IDENTITY_ERROR,
                             UM_IDENTITY_ERROR_VERIFYING,
                             _("Could not finish up sifting through identity credentials in cache: %s"),
                             error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
        }
out:
        krb5_free_principal (self->priv->kerberos_context, principal);
        return verification_level;
}

static gboolean
um_kerberos_identity_is_signed_in (UmIdentity *identity)
{
        UmKerberosIdentity *self = UM_KERBEROS_IDENTITY (identity);
        VerificationLevel verification_level;

        um_kerberos_identity_block_updates (self);
        verification_level = verify_identity (self, NULL);
        um_kerberos_identity_stop_blocking_updates (self);

        return verification_level == VERIFICATION_LEVEL_SIGNED_IN;
}

static void
identity_interface_init (UmIdentityInterface *interface)
{
        interface->get_identifier = um_kerberos_identity_get_identifier;
        interface->is_signed_in = um_kerberos_identity_is_signed_in;
}

static void
set_cancelled_error (GError **error)
{
    g_set_error (error,
                 G_IO_ERROR,
                 G_IO_ERROR_CANCELLED,
                 "%s",
                 _("Operation was cancelled"));
}

static void
on_expiration_alarm_fired (UmAlarm  *alarm,
                           gpointer  user_data)
{
        UmKerberosIdentity *self = UM_KERBEROS_IDENTITY (user_data);
        VerificationLevel verification_level;

        um_kerberos_identity_block_updates (self);
        verification_level = verify_identity (self, NULL);

        if (verification_level != VERIFICATION_LEVEL_SIGNED_IN) {
                g_signal_emit (G_OBJECT (self), signals[EXPIRED], 0);
                um_kerberos_identity_stop_blocking_updates (self);
        } else {
                um_kerberos_identity_stop_blocking_updates (self);
                set_expiration_alarm (self);
        }

}

static void
on_expiration_alarm_rearmed (UmAlarm  *alarm,
                             gpointer  user_data)
{
        UmKerberosIdentity *self = UM_KERBEROS_IDENTITY (user_data);
        VerificationLevel verification_level;

        um_kerberos_identity_block_updates (self);
        verification_level = verify_identity (self, NULL);

        if (verification_level == VERIFICATION_LEVEL_SIGNED_IN) {
                g_signal_emit (G_OBJECT (self), signals[UNEXPIRED], 0);
                um_kerberos_identity_stop_blocking_updates (self);
                set_expiration_alarm (self);
        } else {
                um_kerberos_identity_stop_blocking_updates (self);
        }
}

static void
set_expiration_alarm (UmKerberosIdentity *self)
{
        GDateTime *expiration_time;

        expiration_time = g_date_time_new_from_unix_local (self->priv->expiration_time);
        g_signal_handlers_disconnect_by_func (G_OBJECT (self->priv->expiration_alarm),
                                              G_CALLBACK (on_expiration_alarm_fired),
                                              self);
        g_signal_connect (G_OBJECT (self->priv->expiration_alarm),
                          "fired",
                          G_CALLBACK (on_expiration_alarm_fired),
                          self);
        g_signal_handlers_disconnect_by_func (G_OBJECT (self->priv->expiration_alarm),
                                              G_CALLBACK (on_expiration_alarm_rearmed),
                                              self);
        g_signal_connect (G_OBJECT (self->priv->expiration_alarm),
                          "rearmed",
                          G_CALLBACK (on_expiration_alarm_rearmed),
                          self);

        if (self->priv->expiration_alarm_cancellable != NULL) {
                g_object_unref (self->priv->expiration_alarm_cancellable);
                self->priv->expiration_alarm_cancellable = NULL;
        }

        self->priv->expiration_alarm_cancellable = g_cancellable_new ();
        um_alarm_set (self->priv->expiration_alarm,
                      expiration_time,
                      self->priv->expiration_alarm_cancellable);
        g_date_time_unref (expiration_time);
}

static gboolean
um_kerberos_identity_initable_init (GInitable     *initable,
                                    GCancellable  *cancellable,
                                    GError       **error)
{
        UmKerberosIdentity *self = UM_KERBEROS_IDENTITY (initable);
        GError *verification_error;
        VerificationLevel verification_level;

        if (g_cancellable_is_cancelled (cancellable)) {
                set_cancelled_error (error);
                return FALSE;
        }

        verification_error = NULL;
        verification_level = verify_identity (self, &verification_error);

        switch (verification_level) {
                case VERIFICATION_LEVEL_EXISTS:
                    set_expiration_alarm (self);
                    return TRUE;

                case VERIFICATION_LEVEL_SIGNED_IN:
                    set_expiration_alarm (self);
                    return TRUE;

                case VERIFICATION_LEVEL_ERROR:
                    g_propagate_error (error, verification_error);
                    return FALSE;

                case VERIFICATION_LEVEL_UNVERIFIED:
                default:
                    g_set_error (error,
                                 UM_IDENTITY_ERROR,
                                 UM_IDENTITY_ERROR_VERIFYING,
                                 _("No associated identification found"));

                    return FALSE;
        }
}

static void
initable_interface_init (GInitableIface *interface)
{
        interface->init = um_kerberos_identity_initable_init;
}

void
um_kerberos_identity_update (UmKerberosIdentity *self,
                             UmKerberosIdentity *new_identity)
{
        char *new_principal_name;
        VerificationLevel verification_level;

        g_rec_mutex_lock (&self->priv->updates_lock);

        if (self->priv->credentials_cache != NULL) {
                krb5_cc_close (self->priv->kerberos_context, self->priv->credentials_cache);
        }
        krb5_cc_dup (new_identity->priv->kerberos_context,
                     new_identity->priv->credentials_cache,
                     &self->priv->credentials_cache);

        if (!g_cancellable_is_cancelled (self->priv->expiration_alarm_cancellable)) {
                g_cancellable_cancel (self->priv->expiration_alarm_cancellable);
        }

        new_principal_name = get_principal_name (self, FALSE);
        if (g_strcmp0 (self->priv->identifier, new_principal_name) != 0) {
                g_free (self->priv->identifier);
                self->priv->identifier = new_principal_name;
        } else {
                g_free (new_principal_name);
        }

        g_free (self->priv->cached_realm_name);
        self->priv->cached_realm_name = get_realm_name (self);

        g_free (self->priv->cached_principal_name);
        self->priv->cached_principal_name = get_principal_name (self, TRUE);

        verification_level = verify_identity (self, NULL);

        if (verification_level == VERIFICATION_LEVEL_SIGNED_IN ||
            verification_level == VERIFICATION_LEVEL_EXISTS) {
                set_expiration_alarm (self);
        }

        g_rec_mutex_unlock (&self->priv->updates_lock);
}

gboolean
um_kerberos_identity_erase  (UmKerberosIdentity  *self,
                             GError             **error)
{
        krb5_error_code error_code = 0;

        g_rec_mutex_lock (&self->priv->updates_lock);

        if (self->priv->credentials_cache != NULL) {
                error_code = krb5_cc_destroy (self->priv->kerberos_context,
                                              self->priv->credentials_cache);
                self->priv->credentials_cache = NULL;
        }

        g_rec_mutex_unlock (&self->priv->updates_lock);

        if (error_code != 0) {
                const char *error_message;
                error_message = krb5_get_error_message (self->priv->kerberos_context, error_code);

                g_set_error (error,
                             UM_IDENTITY_ERROR,
                             UM_IDENTITY_ERROR_ERASING,
                             _("Could not erase identity: %s"),
                             error_message);
                krb5_free_error_message (self->priv->kerberos_context, error_message);
                return FALSE;
        }

        return TRUE;
}

void
um_kerberos_identity_block_updates (UmKerberosIdentity *self)
{
        g_rec_mutex_lock (&self->priv->updates_lock);
}

void
um_kerberos_identity_stop_blocking_updates (UmKerberosIdentity *self)
{
        g_rec_mutex_unlock (&self->priv->updates_lock);
}

UmIdentity *
um_kerberos_identity_new (krb5_context context,
                          krb5_ccache  cache)
{
        UmKerberosIdentity *self;
        GError *error;

        self = UM_KERBEROS_IDENTITY (g_object_new (UM_TYPE_KERBEROS_IDENTITY, NULL));

        krb5_cc_dup (context,
                     cache,
                     &self->priv->credentials_cache);
        self->priv->kerberos_context = context;

        error = NULL;
        if (!g_initable_init (G_INITABLE (self), NULL, &error)) {
                g_debug ("Could not create kerberos identity: %s",
                         error->message);
                g_error_free (error);
                g_object_unref (self);
                return NULL;
        }

        return UM_IDENTITY (self);
}
