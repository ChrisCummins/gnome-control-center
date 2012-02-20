/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Authors: Ray Strode
 */

#ifndef __UM_KERBEROS_IDENTITY_H__
#define __UM_KERBEROS_IDENTITY_H__

#include <glib.h>
#include <glib-object.h>

#include <krb5.h>

G_BEGIN_DECLS

#define UM_TYPE_KERBEROS_IDENTITY             (um_kerberos_identity_get_type ())
#define UM_KERBEROS_IDENTITY(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), UM_TYPE_KERBEROS_IDENTITY, UmKerberosIdentity))
#define UM_KERBEROS_IDENTITY_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), UM_TYPE_KERBEROS_IDENTITY, UmKerberosIdentityClass))
#define UM_IS_KERBEROS_IDENTITY(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), UM_TYPE_KERBEROS_IDENTITY))
#define UM_IS_KERBEROS_IDENTITY_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), UM_TYPE_KERBEROS_IDENTITY))
#define UM_KERBEROS_IDENTITY_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), UM_TYPE_KERBEROS_IDENTITY, UmKerberosIdentityClass))

typedef struct _UmKerberosIdentity        UmKerberosIdentity;
typedef struct _UmKerberosIdentityClass   UmKerberosIdentityClass;
typedef struct _UmKerberosIdentityPrivate UmKerberosIdentityPrivate;
typedef enum _UmKerberosIdentityDescriptionLevel UmKerberosIdentityDescriptionLevel;

enum _UmKerberosIdentityDescriptionLevel
{
        UM_KERBEROS_IDENTITY_DESCRIPTION_REALM,
        UM_KERBEROS_IDENTITY_DESCRIPTION_USERNAME_AND_REALM,
        UM_KERBEROS_IDENTITY_DESCRIPTION_USERNAME_ROLE_AND_REALM
};

struct _UmKerberosIdentity
{
        GObject            parent;

        UmKerberosIdentityPrivate *priv;
};

struct _UmKerberosIdentityClass
{
        GObjectClass parent_class;
};

GType         um_kerberos_identity_get_type (void);

UmIdentity   *um_kerberos_identity_new      (krb5_context  kerberos_context,
                                             krb5_ccache   cache);
void          um_kerberos_identity_update (UmKerberosIdentity *identity,
                                           UmKerberosIdentity *new_identity);
gboolean      um_kerberos_identity_erase  (UmKerberosIdentity  *self,
                                           GError             **error);
char         *um_kerberos_identity_get_principal_name (UmKerberosIdentity *self);
char         *um_kerberos_identity_get_realm_name     (UmKerberosIdentity *self);

void          um_kerberos_identity_block_updates (UmKerberosIdentity *identity);
void          um_kerberos_identity_stop_blocking_updates (UmKerberosIdentity *identity);
G_END_DECLS

#endif /* __UM_KERBEROS_IDENTITY_H__ */
