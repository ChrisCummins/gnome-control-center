/*
 * Copyright (C) 2013 Red Hat, Inc.
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
 * Written by:
 *     Matthias Clasen
 */

#define _GNU_SOURCE
#include <config.h>
#include "cc-format-chooser.h"

#include <locale.h>
#include <langinfo.h>
#include <string.h>
#include <glib/gi18n.h>

#include "egg-list-box/egg-list-box.h"

#include "cc-common-language.h"
#include "cc-util.h"

#define GNOME_DESKTOP_USE_UNSTABLE_API
#include <libgnome-desktop/gnome-languages.h>


typedef struct {
        GtkWidget *no_results;
        GtkWidget *more_item;
        GtkWidget *filter_entry;
        GtkWidget *list;
        GtkWidget *scrolledwindow;
        GtkWidget *full_date;
        GtkWidget *medium_date;
        GtkWidget *short_date;
        GtkWidget *time;
        GtkWidget *number;
        GtkWidget *measurement;
        GtkWidget *paper;
        gboolean adding;
        gboolean showing_extra;
        gchar *region;
        gchar **filter_words;
} CcFormatChooserPrivate;

#define GET_PRIVATE(chooser) ((CcFormatChooserPrivate *) g_object_get_data (G_OBJECT (chooser), "private"))

static void
display_date (GtkWidget *label, GDateTime *dt, const gchar *format)
{
        gchar *s;
        s = g_date_time_format (dt, format);
        s = g_strstrip (s);
        gtk_label_set_text (GTK_LABEL (label), s);
        g_free (s);
}

static void
update_format_examples (GtkDialog *chooser)
{
        CcFormatChooserPrivate *priv = GET_PRIVATE (chooser);
        gchar *locale;
        GDateTime *dt;
        gchar *s;
        const gchar *fmt;
        GtkPaperSize *paper;

        locale = g_strdup (setlocale (LC_TIME, NULL));
        setlocale (LC_TIME, priv->region);

        dt = g_date_time_new_now_local ();
        display_date (priv->full_date, dt, "%A %e %B %Y");
        display_date (priv->medium_date, dt, "%e %b %Y");
        display_date (priv->short_date, dt, "%x");
        display_date (priv->time, dt, "%X");

        setlocale (LC_TIME, locale);
        g_free (locale);

        locale = g_strdup (setlocale (LC_NUMERIC, NULL));
        setlocale (LC_NUMERIC, priv->region);

        s = g_strdup_printf ("%'.2f", 123456789.00);
        gtk_label_set_text (GTK_LABEL (priv->number), s);
        g_free (s);

        setlocale (LC_NUMERIC, locale);
        g_free (locale);

#if 0
        locale = g_strdup (setlocale (LC_MONETARY, NULL));
        setlocale (LC_MONETARY, priv->region);

        num_info = localeconv ();
        if (num_info != NULL)
                gtk_label_set_text (GTK_LABEL (priv->currency), num_info->currency_symbol);

        setlocale (LC_MONETARY, locale);
        g_free (locale);
#endif

#ifdef LC_MEASUREMENT
        locale = g_strdup (setlocale (LC_MEASUREMENT, NULL));
        setlocale (LC_MEASUREMENT, priv->region);

        fmt = nl_langinfo (_NL_MEASUREMENT_MEASUREMENT);
        if (fmt && *fmt == 2)
                gtk_label_set_text (GTK_LABEL (priv->measurement), C_("measurement format", "Imperial"));
        else
                gtk_label_set_text (GTK_LABEL (priv->measurement), C_("measurement format", "Metric"));

        setlocale (LC_MEASUREMENT, locale);
        g_free (locale);
#endif

#ifdef LC_PAPER
        locale = g_strdup (setlocale (LC_PAPER, NULL));
        setlocale (LC_PAPER, priv->region);

        paper = gtk_paper_size_new (gtk_paper_size_get_default ());
        gtk_label_set_text (GTK_LABEL (priv->paper), gtk_paper_size_get_display_name (paper));
        gtk_paper_size_free (paper);

        setlocale (LC_PAPER, locale);
        g_free (locale);
#endif
}

static void
set_locale_id (GtkDialog   *chooser,
               const gchar *locale_id)
{
        CcFormatChooserPrivate *priv = GET_PRIVATE (chooser);
        GList *children, *l;

        children = gtk_container_get_children (GTK_CONTAINER (priv->list));
        for (l = children; l; l = l->next) {
                GtkWidget *row = l->data;
                GtkWidget *check = g_object_get_data (G_OBJECT (row), "check");
                const gchar *region = g_object_get_data (G_OBJECT (row), "locale-id");
                if (check == NULL || region == NULL)
                        continue;

                if (g_strcmp0 (locale_id, region) == 0) {
                        gboolean is_extra;

                        /* mark as selected */
                        gtk_widget_set_opacity (check, 1.0);

                        /* make sure this row is shown */
                        is_extra = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (row), "is-extra"));
                        if (!priv->showing_extra && is_extra) {
                                g_object_set_data (G_OBJECT (row), "is-extra", GINT_TO_POINTER (FALSE));
                                egg_list_box_refilter (EGG_LIST_BOX (priv->list));
                        }

                } else {
                        /* mark as unselected */
                        gtk_widget_set_opacity (check, 0.0);
                }
        }
        g_list_free (children);

        g_free (priv->region);
        priv->region = g_strdup (locale_id);

        update_format_examples (chooser);
}

static gint
sort_regions (gconstpointer a,
              gconstpointer b,
              gpointer      data)
{
        const gchar *la;
        const gchar *lb;

        if (g_object_get_data (G_OBJECT (a), "locale-id") == NULL)
                return 1;
        if (g_object_get_data (G_OBJECT (b), "locale-id") == NULL)
                return -1;

        la = g_object_get_data (G_OBJECT (a), "locale-name");
        lb = g_object_get_data (G_OBJECT (b), "locale-name");

        return g_strcmp0 (la, lb);
}

static GtkWidget *
padded_label_new (char *text, gboolean narrow)
{
        GtkWidget *widget;

        widget = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
        gtk_widget_set_halign (widget, GTK_ALIGN_CENTER);
        gtk_widget_set_margin_top (widget, 10);
        gtk_widget_set_margin_bottom (widget, 10);
        gtk_widget_set_margin_left (widget, narrow ? 10 : 80);
        gtk_widget_set_margin_right (widget, narrow ? 10 : 80);
        gtk_box_pack_start (GTK_BOX (widget), gtk_label_new (text), FALSE, FALSE, 0);

        return widget;
}

static GtkWidget *
region_widget_new (const gchar *locale_id,
                   gboolean     is_extra)
{
        gchar *locale_name;
        gchar *locale_current_name;
        gchar *locale_untranslated_name;
        GtkWidget *widget;
        GtkWidget *check;

        locale_name = gnome_get_country_from_locale (locale_id, locale_id);
        locale_current_name = gnome_get_country_from_locale (locale_id, NULL);
        locale_untranslated_name = gnome_get_country_from_locale (locale_id, "C");

        widget = padded_label_new (locale_name, is_extra);

        /* We add a check on each side of the label to keep it centered. */
        check = gtk_image_new ();
        gtk_image_set_from_icon_name (GTK_IMAGE (check), "object-select-symbolic", GTK_ICON_SIZE_MENU);
        gtk_widget_set_opacity (check, 0.0);
        g_object_set (check, "icon-size", GTK_ICON_SIZE_MENU, NULL);
        gtk_box_pack_start (GTK_BOX (widget), check, FALSE, FALSE, 0);
        gtk_box_reorder_child (GTK_BOX (widget), check, 0);

        check = gtk_image_new ();
        gtk_image_set_from_icon_name (GTK_IMAGE (check), "object-select-symbolic", GTK_ICON_SIZE_MENU);
        gtk_widget_set_opacity (check, 0.0);
        g_object_set (check, "icon-size", GTK_ICON_SIZE_MENU, NULL);
        gtk_box_pack_start (GTK_BOX (widget), check, FALSE, FALSE, 0);

        g_object_set_data (G_OBJECT (widget), "check", check);
        g_object_set_data_full (G_OBJECT (widget), "locale-id", g_strdup (locale_id), g_free);
        g_object_set_data_full (G_OBJECT (widget), "locale-name", locale_name, g_free);
        g_object_set_data_full (G_OBJECT (widget), "locale-current-name", locale_current_name, g_free);
        g_object_set_data_full (G_OBJECT (widget), "locale-untranslated-name", locale_untranslated_name, g_free);
        g_object_set_data (G_OBJECT (widget), "is-extra", GUINT_TO_POINTER (is_extra));

        return widget;
}

static GtkWidget *
more_widget_new (void)
{
        GtkWidget *widget;
        GtkWidget *arrow;

        widget = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
        gtk_widget_set_tooltip_text (widget, _("More…"));

        arrow = gtk_image_new_from_icon_name ("view-more-symbolic", GTK_ICON_SIZE_MENU);
        gtk_style_context_add_class (gtk_widget_get_style_context (arrow), "dim-label");
        gtk_widget_set_margin_top (widget, 10);
        gtk_widget_set_margin_bottom (widget, 10);
        gtk_misc_set_alignment (GTK_MISC (arrow), 0.5, 0.5);
        gtk_box_pack_start (GTK_BOX (widget), arrow, TRUE, TRUE, 0);

        return widget;
}

static GtkWidget *
no_results_widget_new (void)
{
        GtkWidget *widget;

        widget = padded_label_new (_("No regions found"), TRUE);
        gtk_widget_set_sensitive (widget, FALSE);
        return widget;
}

static void
add_regions (GtkDialog   *chooser,
             gchar      **locale_ids,
             GHashTable  *initial)
{
        CcFormatChooserPrivate *priv = GET_PRIVATE (chooser);

        priv->adding = TRUE;

        while (*locale_ids) {
                gchar *locale_id;
                gboolean is_initial;
                GtkWidget *widget;

                locale_id = *locale_ids;
                locale_ids ++;

                if (!cc_common_language_has_font (locale_id))
                        continue;

                is_initial = (g_hash_table_lookup (initial, locale_id) != NULL);
                widget = region_widget_new (locale_id, !is_initial);
                gtk_container_add (GTK_CONTAINER (priv->list), widget);
        }

        gtk_container_add (GTK_CONTAINER (priv->list), priv->more_item);
        gtk_container_add (GTK_CONTAINER (priv->list), priv->no_results);

        gtk_widget_show_all (priv->list);

        priv->adding = FALSE;
}

static void
add_all_regions (GtkDialog *chooser)
{
        gchar **locale_ids;
        GHashTable *initial;

        locale_ids = gnome_get_all_locales ();
        initial = cc_common_language_get_initial_languages ();
        add_regions (chooser, locale_ids, initial);
        g_hash_table_destroy (initial);
        g_strfreev (locale_ids);
}

static gboolean
match_all (gchar       **words,
           const gchar  *str)
{
        gchar **w;

        for (w = words; *w; ++w)
                if (!strstr (str, *w))
                        return FALSE;

        return TRUE;
}

static gboolean
region_visible (GtkWidget *child,
                gpointer   user_data)
{
        GtkDialog *chooser = user_data;
        CcFormatChooserPrivate *priv = GET_PRIVATE (chooser);
        gchar *locale_name = NULL;
        gchar *locale_current_name = NULL;
        gchar *locale_untranslated_name = NULL;
        gboolean is_extra;
        gboolean visible;

        if (child == priv->more_item)
                return !priv->showing_extra;

        /* We hide this in the after-refilter handler below. */
        if (child == priv->no_results)
                return TRUE;

        is_extra = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (child), "is-extra"));

        if (!priv->showing_extra && is_extra)
                return FALSE;

        if (!priv->filter_words)
                return TRUE;

        visible = FALSE;

        locale_name =
                cc_util_normalize_casefold_and_unaccent (g_object_get_data (G_OBJECT (child), "locale-name"));
        visible = match_all (priv->filter_words, locale_name);
        if (visible)
                 goto out;

        locale_current_name =
                cc_util_normalize_casefold_and_unaccent (g_object_get_data (G_OBJECT (child), "locale-current-name"));
        visible = match_all (priv->filter_words, locale_current_name);
        if (visible)
                 goto out;

        locale_untranslated_name =
                cc_util_normalize_casefold_and_unaccent (g_object_get_data (G_OBJECT (child), "locale-untranslated-name"));
        visible = match_all (priv->filter_words, locale_untranslated_name);

out:
        g_free (locale_untranslated_name);
        g_free (locale_current_name);
        g_free (locale_name);
        return visible;
}

static void
filter_changed (GtkDialog *chooser)
{
        CcFormatChooserPrivate *priv = GET_PRIVATE (chooser);
        gchar *filter_contents = NULL;

        g_clear_pointer (&priv->filter_words, g_strfreev);

        filter_contents =
                cc_util_normalize_casefold_and_unaccent (gtk_entry_get_text (GTK_ENTRY (priv->filter_entry)));
        if (!filter_contents) {
                egg_list_box_refilter (EGG_LIST_BOX (priv->list));
                return;
        }
        priv->filter_words = g_strsplit_set (g_strstrip (filter_contents), " ", 0);
        g_free (filter_contents);
        egg_list_box_refilter (EGG_LIST_BOX (priv->list));
}

static void
show_more (GtkDialog *chooser)
{
        CcFormatChooserPrivate *priv = GET_PRIVATE (chooser);
        GtkWidget *widget;
        gint width, height;

        gtk_window_get_size (GTK_WINDOW (chooser), &width, &height);
        gtk_widget_set_size_request (GTK_WIDGET (chooser), width, height);
        gtk_window_set_resizable (GTK_WINDOW (chooser), TRUE);

        widget = priv->scrolledwindow;
        gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (widget),
                                        GTK_POLICY_NEVER,
                                        GTK_POLICY_AUTOMATIC);

        gtk_widget_show (priv->filter_entry);
        gtk_widget_grab_focus (priv->filter_entry);

        priv->showing_extra = TRUE;

        egg_list_box_refilter (EGG_LIST_BOX (priv->list));
}

static void
child_activated (EggListBox  *box,
                 GtkWidget   *child,
                 GtkDialog   *chooser)
{
        CcFormatChooserPrivate *priv = GET_PRIVATE (chooser);
        gchar *new_locale_id;

        if (priv->adding)
                return;

        if (child == NULL)
                return;

        if (child == priv->no_results)
                return;

        if (child == priv->more_item) {
                show_more (chooser);
                return;
        }
        new_locale_id = g_object_get_data (G_OBJECT (child), "locale-id");
        set_locale_id (chooser, new_locale_id);
}

typedef struct {
        gint count;
        GtkWidget *ignore;
} CountChildrenData;

static void
count_visible_children (GtkWidget *widget,
                        gpointer   user_data)
{
        CountChildrenData *data = user_data;
        if (widget!= data->ignore &&
            gtk_widget_get_child_visible (widget) &&
            gtk_widget_get_visible (widget))
                data->count++;
}

static void
end_refilter (EggListBox *list_box,
              gpointer    user_data)
{
        GtkDialog *chooser = user_data;
        CcFormatChooserPrivate *priv = GET_PRIVATE (chooser);
        CountChildrenData data = { 0 };

        data.ignore = priv->no_results;
        gtk_container_foreach (GTK_CONTAINER (list_box),
                               count_visible_children, &data);

        gtk_widget_set_visible (priv->no_results, (data.count == 0));
}

static void
update_separator_func (GtkWidget **separator,
                       GtkWidget  *child,
                       GtkWidget  *before,
                       gpointer    user_data)
{
        if (before == NULL)
                return;

        if (*separator == NULL) {
                *separator = gtk_separator_new (GTK_ORIENTATION_HORIZONTAL);
                g_object_ref_sink (*separator);
                gtk_widget_show (*separator);
        }
}

static void
cc_format_chooser_private_free (gpointer data)
{
        CcFormatChooserPrivate *priv = data;

        g_strfreev (priv->filter_words);
        g_free (priv->region);
        g_free (priv);
}

#define WID(name) ((GtkWidget *) gtk_builder_get_object (builder, name))

GtkWidget *
cc_format_chooser_new (GtkWidget *parent)
{
        GtkBuilder *builder;
        GtkWidget *chooser;
        CcFormatChooserPrivate *priv;
        GError *error = NULL;

        builder = gtk_builder_new ();
        if (gtk_builder_add_from_resource (builder, "/org/gnome/control-center/region/format-chooser.ui", &error) == 0) {
                g_object_unref (builder);
                g_warning ("failed to load format chooser: %s", error->message);
                g_error_free (error);
                return NULL;
        }

        chooser = WID ("dialog");
        priv = g_new0 (CcFormatChooserPrivate, 1);
        g_object_set_data_full (G_OBJECT (chooser), "private", priv, cc_format_chooser_private_free);
        g_object_set_data_full (G_OBJECT (chooser), "builder", builder, g_object_unref);

        priv->filter_entry = WID ("region-filter-entry");
        priv->list = WID ("region-list");
        priv->scrolledwindow = WID ("region-scrolledwindow");
        priv->more_item = more_widget_new ();
        priv->no_results = no_results_widget_new ();

        priv->full_date = WID ("full-date-format");
        priv->medium_date = WID ("medium-date-format");
        priv->short_date = WID ("short-date-format");
        priv->time = WID ("time-format");
        priv->number = WID ("number-format");
        priv->measurement = WID ("measurement-format");
        priv->paper = WID ("paper-format");

        egg_list_box_set_adjustment (EGG_LIST_BOX (priv->list),
                                     gtk_scrolled_window_get_vadjustment (GTK_SCROLLED_WINDOW (priv->scrolledwindow)));

        egg_list_box_set_sort_func (EGG_LIST_BOX (priv->list),
                                    sort_regions, chooser, NULL);
        egg_list_box_set_filter_func (EGG_LIST_BOX (priv->list),
                                      region_visible, chooser, NULL);
        egg_list_box_set_selection_mode (EGG_LIST_BOX (priv->list),
                                         GTK_SELECTION_NONE);
        egg_list_box_set_separator_funcs (EGG_LIST_BOX (priv->list),
                                          update_separator_func, NULL, NULL);

        add_all_regions (GTK_DIALOG (chooser));

        g_signal_connect_swapped (priv->filter_entry, "changed",
                                  G_CALLBACK (filter_changed), chooser);

        g_signal_connect (priv->list, "child-activated",
                          G_CALLBACK (child_activated), chooser);

        g_signal_connect_after (priv->list, "refilter",
                                G_CALLBACK (end_refilter), chooser);

        egg_list_box_refilter (EGG_LIST_BOX (priv->list));

        gtk_window_set_transient_for (GTK_WINDOW (chooser), GTK_WINDOW (parent));

        return chooser;
}

void
cc_format_chooser_clear_filter (GtkWidget *chooser)
{
        CcFormatChooserPrivate *priv = GET_PRIVATE (chooser);

        gtk_entry_set_text (GTK_ENTRY (priv->filter_entry), "");
}

const gchar *
cc_format_chooser_get_region (GtkWidget *chooser)
{
        CcFormatChooserPrivate *priv = GET_PRIVATE (chooser);

        return priv->region;
}

void
cc_format_chooser_set_region (GtkWidget   *chooser,
                              const gchar *region)
{
        set_locale_id (GTK_DIALOG (chooser), region);
}
