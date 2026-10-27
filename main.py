"""
Text Finder Mobile (Flet Edition)
Aplikasi pencarian teks & pemilah cookies/credentials berkinerja tinggi,
dirancang khusus untuk perangkat Android (APK) dan Desktop.
"""

import os
import sys
import threading
import time
import asyncio
from datetime import datetime
import flet as ft

from text_finder_core import (
    SearchEngine,
    export_split_results,
    format_size,
    extract_cookie_domain,
    extract_cred_domain
)

# ── Flet 0.x / 1.0+ Compatibility Layer ──
if not hasattr(ft, "ElevatedButton"):
    ft.ElevatedButton = getattr(ft, "Button", getattr(ft, "FilledButton", None))

if hasattr(ft, "Padding"):
    for _attr in ["symmetric", "only", "all", "zero"]:
        if hasattr(ft.Padding, _attr) and not hasattr(ft.padding, _attr):
            setattr(ft.padding, _attr, getattr(ft.Padding, _attr))

if hasattr(ft, "Margin"):
    for _attr in ["symmetric", "only", "all", "zero"]:
        if hasattr(ft.Margin, _attr) and not hasattr(ft.margin, _attr):
            setattr(ft.margin, _attr, getattr(ft.Margin, _attr))



def main(page: ft.Page):
    # ── Page Configuration ──
    page.title = "Text Finder"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 0
    page.spacing = 0

    # ── Global App State ──
    app_state = {
        "folder": os.path.abspath(os.getcwd()),
        "keyword": "",
        "scan_all": False,
        "case_sensitive": False,
        "is_regex": False,
        "dedup": True,
        "context_lines": 2,
        "results": [],             # Full master results
        "seen_keys": set(),
        "filtered_results": [],
        "filter_type": "all",      # 'all' | 'cookie' | 'credential'
        "filter_query": "",
        "is_searching": False,
        "stop_event": None,
        "total_files": 0,
        "done_files": 0,
        "total_bytes": 0,
        "done_bytes": 0,
        "large_files": {},
        "search_start": None,
        "discovery_done": False,
    }

    # Setup Clipboard helper
    clipboard = ft.Clipboard()

    # ── Safe UI Update (Thread-safe for Flet 1.0) ──
    def safe_update():
        try:
            if hasattr(page, "schedule_update"):
                page.schedule_update()
            else:
                page.update()
        except Exception:
            pass

    # ── Helpers ──
    def show_snack(text: str, is_error: bool = False):
        snack = ft.SnackBar(
            content=ft.Text(text, color=ft.Colors.WHITE),
            bgcolor=ft.Colors.RED_700 if is_error else ft.Colors.GREEN_700,
            open=True,
            duration=3500
        )
        page.overlay.append(snack)
        safe_update()

    # ── Pickers ──
    def on_folder_selected(e: ft.FilePickerResultEvent):
        if e.path:
            folder_input.value = e.path
            app_state["folder"] = e.path
            safe_update()

    def on_export_folder_selected(e: ft.FilePickerResultEvent):
        if e.path:
            export_folder_input.value = e.path
            safe_update()

    folder_picker = ft.FilePicker(on_result=on_folder_selected)
    export_folder_picker = ft.FilePicker(on_result=on_export_folder_selected)

    # In Flet < 1.0, non-visual services were required in page.overlay
    if not hasattr(page, "services"):
        page.overlay.extend([clipboard, folder_picker, export_folder_picker])

    async def select_folder(_):
        try:
            res = folder_picker.get_directory_path("Pilih Folder Dokumen/TXT")
            if asyncio.iscoroutine(res):
                path = await res
                if path:
                    folder_input.value = path
                    app_state["folder"] = path
                    safe_update()
        except Exception as ex:
            show_snack(f"Gagal memilih folder: {ex}", is_error=True)

    async def select_export_folder(_):
        try:
            res = export_folder_picker.get_directory_path("Pilih Folder Tujuan Simpan")
            if asyncio.iscoroutine(res):
                path = await res
                if path:
                    export_folder_input.value = path
                    safe_update()
        except Exception as ex:
            show_snack(f"Gagal memilih folder: {ex}", is_error=True)

    # ── UI Controls: TAB 1 (Pencarian) ──
    # Check default path: On Android, default to Download folder if it exists
    android_download = "/storage/emulated/0/Download"
    initial_folder = android_download if os.path.exists(android_download) else app_state["folder"]

    folder_input = ft.TextField(
        label="Folder Target (.txt)",
        value=initial_folder,
        prefix_icon=ft.Icons.FOLDER_OPEN_ROUNDED,
        dense=True,
        expand=True,
    )

    btn_browse_folder = ft.IconButton(
        icon=ft.Icons.DRIVE_FILE_MOVE_OUTLINED,
        tooltip="Pilih Folder",
        on_click=select_folder
    )

    kw_input = ft.TextField(
        label="Kata Kunci / Keyword",
        hint_text="Misal: netflix, user:pass, @gmail.com",
        prefix_icon=ft.Icons.SEARCH_ROUNDED,
        dense=True,
    )

    def on_scan_all_toggle(e):
        is_scan_all = scan_all_switch.value
        app_state["scan_all"] = is_scan_all
        kw_input.disabled = is_scan_all
        case_switch.disabled = is_scan_all
        regex_switch.disabled = is_scan_all
        page.update()

    scan_all_switch = ft.Switch(
        label="Scan Semua (Deteksi Otomatis Cookie & Kredensial)",
        value=False,
        on_change=on_scan_all_toggle
    )

    case_switch = ft.Switch(label="Case Sensitive", value=False)
    regex_switch = ft.Switch(label="Regex", value=False)
    dedup_switch = ft.Switch(label="Dedup (Hapus Duplikat)", value=True)

    ctx_slider = ft.Slider(
        min=0, max=5, divisions=5, value=2,
        label="{value} Baris Konteks",
    )

    status_text = ft.Text("Siap melakukan pencarian", size=13, color=ft.Colors.ON_SURFACE_VARIANT)
    progress_bar = ft.ProgressBar(value=0, height=8, border_radius=4, color=ft.Colors.PRIMARY)
    
    lbl_stat_files = ft.Text("0 / 0", size=14, weight=ft.FontWeight.BOLD)
    lbl_stat_matches = ft.Text("0 hasil", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.AMBER_400)
    lbl_stat_speed = ft.Text("0 B/detik", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.CYAN_400)
    lbl_stat_bytes = ft.Text("0 B / 0 B", size=14, weight=ft.FontWeight.BOLD)

    def stat_card(title: str, text_ctl: ft.Text, icon: str):
        return ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(icon, size=18, color=ft.Colors.PRIMARY),
                    ft.Text(title, size=11, color=ft.Colors.ON_SURFACE_VARIANT),
                ], spacing=4),
                text_ctl
            ], spacing=2),
            bgcolor=ft.Colors.SURFACE_CONTAINER_HIGH,
            border_radius=8,
            padding=10,
            expand=True
        )

    stats_row = ft.Column([
        ft.Row([
            stat_card("File Dipindai", lbl_stat_files, ft.Icons.DESCRIPTION_ROUNDED),
            stat_card("Hasil Cocok", lbl_stat_matches, ft.Icons.CHECK_CIRCLE_ROUNDED),
        ]),
        ft.Row([
            stat_card("Kecepatan", lbl_stat_speed, ft.Icons.BOLT_ROUNDED),
            stat_card("Ukuran Diproses", lbl_stat_bytes, ft.Icons.DATA_USAGE_ROUNDED),
        ])
    ], spacing=8)

    # ── Search Engine Actions ──
    def stop_search(_=None):
        if app_state["stop_event"]:
            app_state["stop_event"].set()
        app_state["is_searching"] = False
        btn_start_search.visible = True
        btn_stop_search.visible = False
        status_text.value = "Pencarian dihentikan oleh pengguna."
        page.update()

    def run_search_thread():
        folder = folder_input.value.strip()
        keyword = kw_input.value.strip() if not scan_all_switch.value else ""

        if not folder or not os.path.exists(folder):
            show_snack("Folder target tidak valid atau tidak ditemukan!", is_error=True)
            stop_search()
            return

        if not scan_all_switch.value and not keyword:
            show_snack("Masukkan kata kunci pencarian atau aktifkan Scan Semua!", is_error=True)
            stop_search()
            return

        # Reset states
        app_state["results"].clear()
        app_state["seen_keys"].clear()
        app_state["filtered_results"].clear()
        app_state["total_files"] = 0
        app_state["done_files"] = 0
        app_state["total_bytes"] = 0
        app_state["done_bytes"] = 0
        app_state["large_files"].clear()
        app_state["discovery_done"] = False
        app_state["search_start"] = datetime.now()
        app_state["stop_event"] = threading.Event()
        app_state["is_searching"] = True

        engine = SearchEngine(max_workers=min(16, (os.cpu_count() or 4) * 2))

        # Periodic UI update ticker
        def ui_updater():
            while app_state["is_searching"]:
                time.sleep(0.12)
                elapsed = max((datetime.now() - app_state["search_start"]).total_seconds(), 0.1)
                
                partial_bytes = sum(b_read for b_read, _ in app_state["large_files"].values())
                total_done_bytes = app_state["done_bytes"] + partial_bytes
                
                speed_bps = total_done_bytes / elapsed
                lbl_stat_speed.value = f"{format_size(speed_bps)}/detik"

                lbl_stat_files.value = f"{app_state['done_files']:,} / {app_state['total_files']:,}"
                lbl_stat_matches.value = f"{len(app_state['results']):,} hasil"
                lbl_stat_bytes.value = f"{format_size(total_done_bytes)} / {format_size(app_state['total_bytes'])}"

                if app_state["total_bytes"] > 0:
                    pct = min(1.0, total_done_bytes / app_state["total_bytes"])
                    progress_bar.value = pct

                if not app_state["discovery_done"]:
                    status_text.value = f"Mengumpulkan file... ({app_state['total_files']:,} file ditemukan)"
                else:
                    status_text.value = f"Memindai... {app_state['done_files']:,} dari {app_state['total_files']:,} file"

                safe_update()

        threading.Thread(target=ui_updater, daemon=True).start()

        def on_discovered(files_cnt, bytes_cnt):
            app_state["total_files"] += files_cnt
            app_state["total_bytes"] += bytes_cnt

        def on_progress(files_cnt, bytes_cnt, filepath):
            app_state["done_files"] += files_cnt
            app_state["done_bytes"] += bytes_cnt
            app_state["large_files"].pop(filepath, None)

        def on_large_file(filepath, b_read, b_total):
            app_state["large_files"][filepath] = (b_read, b_total)

        def on_results(batch):
            dedup = dedup_switch.value
            valid_batch = []
            for r in batch:
                if dedup:
                    k = (r["type"], r["snippet"].strip().lower())
                    if k in app_state["seen_keys"]:
                        continue
                    app_state["seen_keys"].add(k)
                valid_batch.append(r)
            if valid_batch:
                app_state["results"].extend(valid_batch)

        def on_done():
            app_state["is_searching"] = False
            progress_bar.value = 1.0
            status_text.value = f"Pencarian selesai! Ditemukan {len(app_state['results']):,} hasil."
            btn_start_search.visible = True
            btn_stop_search.visible = False
            apply_filter()
            nav_bar.selected_index = 1
            switch_tab(1)
            safe_update()

        try:
            engine.search(
                folder=folder,
                keyword=keyword,
                case_sensitive=case_switch.value,
                is_regex=regex_switch.value,
                scan_all=scan_all_switch.value,
                context_lines=int(ctx_slider.value),
                stop_event=app_state["stop_event"],
                on_discovered=on_discovered,
                on_progress=on_progress,
                on_large_file=on_large_file,
                on_results=on_results,
                on_done=on_done,
            )
        except Exception as ex:
            show_snack(f"Terjadi kesalahan: {ex}", is_error=True)
            stop_search()

    def start_search(_=None):
        btn_start_search.visible = False
        btn_stop_search.visible = True
        progress_bar.value = None # indeterminate while starting
        status_text.value = "Memulai mesin pencari..."
        page.update()
        if hasattr(page, "run_thread"):
            page.run_thread(run_search_thread)
        else:
            threading.Thread(target=run_search_thread, daemon=True).start()

    btn_start_search = ft.ElevatedButton(
        "Mulai Pencarian",
        icon=ft.Icons.PLAY_ARROW_ROUNDED,
        bgcolor=ft.Colors.PRIMARY,
        color=ft.Colors.ON_PRIMARY,
        height=48,
        expand=True,
        on_click=start_search
    )

    btn_stop_search = ft.OutlinedButton(
        "Hentikan",
        icon=ft.Icons.STOP_ROUNDED,
        style=ft.ButtonStyle(color=ft.Colors.ERROR),
        height=48,
        expand=True,
        visible=False,
        on_click=stop_search
    )

    tab_search = ft.ListView([
        ft.Container(
            content=ft.Column([
                ft.Text("Target Direktori", size=13, weight=ft.FontWeight.BOLD, color=ft.Colors.PRIMARY),
                ft.Row([folder_input, btn_browse_folder], spacing=4),
            ], spacing=6),
            bgcolor=ft.Colors.SURFACE_CONTAINER,
            border_radius=12,
            padding=14,
        ),
        ft.Container(
            content=ft.Column([
                ft.Text("Kriteria Pencarian", size=13, weight=ft.FontWeight.BOLD, color=ft.Colors.PRIMARY),
                kw_input,
                scan_all_switch,
                ft.Divider(height=1),
                ft.Row([case_switch, regex_switch], wrap=True),
                dedup_switch,
                ft.Text("Konteks Sekitar Baris Cocok", size=12, color=ft.Colors.ON_SURFACE_VARIANT),
                ctx_slider,
            ], spacing=6),
            bgcolor=ft.Colors.SURFACE_CONTAINER,
            border_radius=12,
            padding=14,
        ),
        ft.Row([btn_start_search, btn_stop_search]),
        ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.INSIGHTS_ROUNDED, color=ft.Colors.PRIMARY),
                    ft.Text("Live Status & Progress", size=14, weight=ft.FontWeight.BOLD),
                ], spacing=6),
                status_text,
                progress_bar,
                stats_row,
            ], spacing=10),
            bgcolor=ft.Colors.SURFACE_CONTAINER,
            border_radius=12,
            padding=14,
        ),
    ], spacing=12, padding=14, expand=True)

    # ── UI Controls: TAB 2 (Hasil / Results) ──
    filter_search_box = ft.TextField(
        label="Filter hasil...",
        prefix_icon=ft.Icons.FILTER_LIST_ROUNDED,
        dense=True,
        expand=True,
        on_change=lambda _: apply_filter()
    )

    def set_type_filter(t: str):
        app_state["filter_type"] = t
        chip_all.bgcolor = ft.Colors.PRIMARY if t == "all" else ft.Colors.SURFACE_CONTAINER_HIGHEST
        chip_cookie.bgcolor = ft.Colors.GREEN_700 if t == "cookie" else ft.Colors.SURFACE_CONTAINER_HIGHEST
        chip_cred.bgcolor = ft.Colors.AMBER_700 if t == "credential" else ft.Colors.SURFACE_CONTAINER_HIGHEST
        apply_filter()
        page.update()

    chip_all = ft.Container(
        content=ft.Text("Semua (0)", size=12, weight=ft.FontWeight.BOLD),
        padding=ft.padding.symmetric(horizontal=12, vertical=6),
        border_radius=16,
        bgcolor=ft.Colors.PRIMARY,
        on_click=lambda _: set_type_filter("all")
    )

    chip_cookie = ft.Container(
        content=ft.Text("🍪 Cookies (0)", size=12, weight=ft.FontWeight.BOLD),
        padding=ft.padding.symmetric(horizontal=12, vertical=6),
        border_radius=16,
        bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
        on_click=lambda _: set_type_filter("cookie")
    )

    chip_cred = ft.Container(
        content=ft.Text("🔑 Kredensial (0)", size=12, weight=ft.FontWeight.BOLD),
        padding=ft.padding.symmetric(horizontal=12, vertical=6),
        border_radius=16,
        bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
        on_click=lambda _: set_type_filter("credential")
    )

    results_count_lbl = ft.Text("0 data ditampilkan", size=13, color=ft.Colors.ON_SURFACE_VARIANT)
    results_list_view = ft.ListView(spacing=8, expand=True, padding=ft.padding.only(bottom=20))

    def show_context_dialog(result_item: dict):
        ctx_lines = result_item.get("ctx_lines", [])
        ctx_start = result_item.get("ctx_start", 1)
        matched_line_no = result_item.get("lineno", 1)

        code_controls = []
        for idx, line in enumerate(ctx_lines):
            line_no = ctx_start + idx
            is_match = (line_no == matched_line_no)
            code_controls.append(
                ft.Container(
                    content=ft.Row([
                        ft.Text(f"{line_no:4d} |", size=11, font_family="monospace", color=ft.Colors.ON_SURFACE_VARIANT),
                        ft.Text(line, size=11, font_family="monospace", selectable=True,
                                weight=ft.FontWeight.BOLD if is_match else ft.FontWeight.NORMAL,
                                color=ft.Colors.AMBER_300 if is_match else ft.Colors.ON_SURFACE),
                    ], spacing=6),
                    bgcolor=ft.Colors.AMBER_900 if is_match else None,
                    padding=ft.padding.symmetric(horizontal=4, vertical=2),
                    border_radius=4,
                )
            )

        async def copy_snippet(_=None):
            text_to_copy = result_item.get("snippet", "")
            try:
                res = clipboard.set(text_to_copy)
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                pass
            show_snack("Snippet berhasil disalin ke clipboard!")

        dialog = ft.AlertDialog(
            title=ft.Row([
                ft.Icon(ft.Icons.CODE_ROUNDED, color=ft.Colors.PRIMARY),
                ft.Text("Detail & Konteks Baris", size=16, weight=ft.FontWeight.BOLD),
            ], spacing=8),
            content=ft.Container(
                content=ft.Column([
                    ft.Text(f"File: {result_item['filename']}", size=12, color=ft.Colors.ON_SURFACE_VARIANT),
                    ft.Text(f"Domain: {result_item.get('domain', '—')}", size=12, color=ft.Colors.CYAN_400),
                    ft.Divider(height=1),
                    ft.Container(
                        content=ft.ListView(code_controls, spacing=2),
                        height=240,
                        bgcolor=ft.Colors.BLACK54,
                        border_radius=6,
                        padding=8,
                    )
                ], spacing=6, tight=True),
                width=500
            ),
            actions=[
                ft.TextButton("Salin Snippet", icon=ft.Icons.COPY_ALL_ROUNDED, on_click=copy_snippet),
                ft.ElevatedButton("Tutup", on_click=lambda _: page.pop_dialog())
            ]
        )
        page.show_dialog(dialog)
        page.update()

    def build_result_card(r: dict):
        is_cookie = r.get("type") == "cookie"
        is_cred = r.get("type") == "credential"

        type_color = ft.Colors.GREEN_700 if is_cookie else (ft.Colors.AMBER_700 if is_cred else ft.Colors.BLUE_GREY_700)
        type_icon = "🍪" if is_cookie else ("🔑" if is_cred else "📄")
        type_name = "Cookie" if is_cookie else ("Credential" if is_cred else "Teks")

        domain = r.get("domain", "—")

        return ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Container(
                        content=ft.Text(f"{type_icon} {type_name}", size=11, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE),
                        bgcolor=type_color,
                        padding=ft.padding.symmetric(horizontal=8, vertical=3),
                        border_radius=12
                    ),
                    ft.Container(
                        content=ft.Text(domain, size=11, color=ft.Colors.CYAN_200, weight=ft.FontWeight.W_500),
                        bgcolor=ft.Colors.CYAN_900,
                        padding=ft.padding.symmetric(horizontal=8, vertical=3),
                        border_radius=12
                    ),
                    ft.Text(f"Baris {r['lineno']}", size=11, color=ft.Colors.ON_SURFACE_VARIANT),
                ], spacing=6),
                ft.Text(
                    f"{r['filename']}",
                    size=12,
                    weight=ft.FontWeight.BOLD,
                    color=ft.Colors.PRIMARY,
                    max_lines=1,
                    overflow=ft.TextOverflow.ELLIPSIS
                ),
                ft.Container(
                    content=ft.Text(
                        r["snippet"],
                        size=11,
                        font_family="monospace",
                        selectable=True,
                        max_lines=3,
                        overflow=ft.TextOverflow.ELLIPSIS
                    ),
                    bgcolor=ft.Colors.BLACK38,
                    border_radius=6,
                    padding=8,
                    expand=True,
                ),
                ft.Row([
                    ft.TextButton(
                        "Lihat Konteks",
                        icon=ft.Icons.UNFOLD_MORE_ROUNDED,
                        on_click=lambda _, item=r: show_context_dialog(item)
                    ),
                ], alignment=ft.MainAxisAlignment.END)
            ], spacing=6),
            bgcolor=ft.Colors.SURFACE_CONTAINER,
            border_radius=10,
            padding=12,
        )

    def apply_filter():
        q = filter_search_box.value.strip().lower()
        t = app_state["filter_type"]

        # Count types
        c_cookies = sum(1 for r in app_state["results"] if r.get("type") == "cookie")
        c_creds = sum(1 for r in app_state["results"] if r.get("type") == "credential")
        total = len(app_state["results"])

        chip_all.content.value = f"Semua ({total:,})"
        chip_cookie.content.value = f"🍪 Cookies ({c_cookies:,})"
        chip_cred.content.value = f"🔑 Kredensial ({c_creds:,})"

        filtered = []
        for r in app_state["results"]:
            if t != "all" and r.get("type") != t:
                continue
            if q:
                if not (q in r["filename"].lower() or q in r.get("domain", "").lower() or q in r["snippet"].lower()):
                    continue
            filtered.append(r)

        results_count_lbl.value = f"Menampilkan {min(len(filtered), 200):,} dari {len(filtered):,} hasil cocok"

        results_list_view.controls.clear()
        if not filtered:
            results_list_view.controls.append(
                ft.Container(
                    content=ft.Column([
                        ft.Icon(ft.Icons.SEARCH_OFF_ROUNDED, size=48, color=ft.Colors.ON_SURFACE_VARIANT),
                        ft.Text("Tidak ada data yang cocok dengan filter", size=14, color=ft.Colors.ON_SURFACE_VARIANT),
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                    alignment=ft.alignment.center,
                    padding=40
                )
            )
        else:
            # Cap at 200 items in ListView for smooth mobile performance
            for r in filtered[:200]:
                results_list_view.controls.append(build_result_card(r))

        page.update()

    tab_results = ft.Column([
        ft.Container(
            content=ft.Column([
                ft.Row([filter_search_box]),
                ft.Row([chip_all, chip_cookie, chip_cred], scroll=ft.ScrollMode.ADAPTIVE),
                ft.Row([
                    results_count_lbl,
                    ft.ElevatedButton(
                        "Export Hasil",
                        icon=ft.Icons.FILE_DOWNLOAD_ROUNDED,
                        bgcolor=ft.Colors.GREEN_700,
                        color=ft.Colors.WHITE,
                        on_click=lambda _: switch_tab(2)
                    )
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)
            ], spacing=8),
            bgcolor=ft.Colors.SURFACE_CONTAINER,
            padding=12,
            border_radius=10,
        ),
        results_list_view
    ], spacing=10, expand=True)

    # ── UI Controls: TAB 3 (Export & Panduan) ──
    export_folder_input = ft.TextField(
        label="Folder Tujuan Export",
        value=initial_folder,
        prefix_icon=ft.Icons.DRIVE_FILE_MOVE_ROUNDED,
        dense=True,
        expand=True
    )

    btn_browse_export = ft.IconButton(
        icon=ft.Icons.FOLDER_OPEN_ROUNDED,
        tooltip="Pilih Folder Tujuan",
        on_click=select_export_folder
    )

    export_prog_text = ft.Text("", size=13, color=ft.Colors.SECONDARY)
    export_prog_bar = ft.ProgressBar(value=0, height=8, border_radius=4, visible=False)

    def run_export(_=None):
        if not app_state["results"]:
            show_snack("Belum ada hasil pencarian untuk di-export!", is_error=True)
            return

        target_folder = export_folder_input.value.strip()
        if not target_folder:
            show_snack("Tentukan folder tujuan export terlebih dahulu!", is_error=True)
            return

        export_prog_bar.visible = True
        export_prog_bar.value = None
        export_prog_text.value = "Menyiapkan pemilahan data..."
        page.update()

        def on_prog(current, total, status, sub):
            if total > 0:
                export_prog_bar.value = min(1.0, current / total)
            export_prog_text.value = f"{status} {sub}"
            safe_update()

        def on_done(res):
            export_prog_bar.visible = False
            if res.get("error"):
                export_prog_text.value = f"Gagal: {res['error']}"
                show_snack(f"Gagal mengeksport: {res['error']}", is_error=True)
            else:
                msg = (
                    f"✔ Export Berhasil!\n"
                    f"🍪 {res['cookies_saved']:,} cookies dipisah ke {res['domain_cookies_count']:,} domain di /Cookies\n"
                    f"🔑 {res['creds_saved']:,} kredensial dipisah ke {res['domain_creds_count']:,} file di /Credentials"
                )
                export_prog_text.value = "Pemilahan & Export selesai!"
                
                dialog = ft.AlertDialog(
                    title=ft.Row([ft.Icon(ft.Icons.CHECK_CIRCLE, color=ft.Colors.GREEN_400), ft.Text("Export Berhasil")]),
                    content=ft.Text(msg),
                    actions=[ft.ElevatedButton("Tutup", on_click=lambda _: page.pop_dialog())]
                )
                page.show_dialog(dialog)
            safe_update()

        export_split_results(app_state["results"], target_folder, on_progress=on_prog, on_done=on_done)

    tab_export = ft.ListView([
        ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.AUTO_AWESOME_ROUNDED, color=ft.Colors.AMBER_400),
                    ft.Text("Smart Sorter & Auto Export", size=15, weight=ft.FontWeight.BOLD),
                ], spacing=6),
                ft.Text(
                    "Fitur ini memilah seluruh data pencarian secara otomatis:\n"
                    "• Format Netscape Cookie dipisahkan per domain ke folder /Cookies/<domain>/\n"
                    "• Kredensial (email/user:pass) dipisahkan per domain ke /Credentials/<domain>.txt\n"
                    "• Otomatis deduplikasi dan perbaikan format.",
                    size=12,
                    color=ft.Colors.ON_SURFACE_VARIANT
                ),
                ft.Row([export_folder_input, btn_browse_export], spacing=4),
                ft.ElevatedButton(
                    "Mulai Pemilahan & Export",
                    icon=ft.Icons.DRIVE_FILE_MOVE_ROUNDED,
                    bgcolor=ft.Colors.PRIMARY,
                    color=ft.Colors.ON_PRIMARY,
                    height=46,
                    on_click=run_export
                ),
                export_prog_bar,
                export_prog_text,
            ], spacing=10),
            bgcolor=ft.Colors.SURFACE_CONTAINER,
            border_radius=12,
            padding=14,
        ),
        ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.SECURITY_ROUNDED, color=ft.Colors.CYAN_400),
                    ft.Text("Panduan Izin Android (Penting)", size=15, weight=ft.FontWeight.BOLD),
                ], spacing=6),
                ft.Text(
                    "Agar aplikasi dapat membaca ribuan file .txt di penyimpanan HP Android Anda:\n\n"
                    "1. Buka Pengaturan HP > Aplikasi > Text Finder.\n"
                    "2. Pilih menu 'Izin' (Permissions).\n"
                    "3. Aktifkan 'Akses Pengelolaan Semua File' (Manage All Files Access).\n\n"
                    "Lokasi folder umum di Android:\n"
                    "• Folder Download: /storage/emulated/0/Download\n"
                    "• Folder Dokumen: /storage/emulated/0/Documents",
                    size=12,
                    color=ft.Colors.ON_SURFACE_VARIANT
                ),
            ], spacing=8),
            bgcolor=ft.Colors.SURFACE_CONTAINER,
            border_radius=12,
            padding=14,
        ),
    ], spacing=12, padding=14, expand=True)

    # ── Tabs Navigation ──
    current_tab_container = ft.Container(content=tab_search, expand=True, padding=ft.padding.symmetric(horizontal=12, vertical=6))

    def switch_tab(index: int):
        nav_bar.selected_index = index
        if index == 0:
            current_tab_container.content = tab_search
        elif index == 1:
            current_tab_container.content = tab_results
            apply_filter()
        elif index == 2:
            current_tab_container.content = tab_export
        page.update()

    def on_nav_change(e):
        switch_tab(e.control.selected_index)

    nav_bar = ft.NavigationBar(
        destinations=[
            ft.NavigationBarDestination(icon=ft.Icons.SEARCH_ROUNDED, label="Pencarian"),
            ft.NavigationBarDestination(icon=ft.Icons.FORMAT_LIST_BULLETED_ROUNDED, label="Hasil"),
            ft.NavigationBarDestination(icon=ft.Icons.DRIVE_FILE_MOVE_ROUNDED, label="Export & Info"),
        ],
        selected_index=0,
        on_change=on_nav_change
    )

    def toggle_theme(_):
        if page.theme_mode == ft.ThemeMode.DARK:
            page.theme_mode = ft.ThemeMode.LIGHT
            theme_btn.icon = ft.Icons.DARK_MODE_ROUNDED
        else:
            page.theme_mode = ft.ThemeMode.DARK
            theme_btn.icon = ft.Icons.LIGHT_MODE_ROUNDED
        page.update()

    theme_btn = ft.IconButton(
        icon=ft.Icons.LIGHT_MODE_ROUNDED,
        tooltip="Ganti Tema",
        on_click=toggle_theme
    )

    page.appbar = ft.AppBar(
        leading=ft.Icon(ft.Icons.SEARCH_ROUNDED, color=ft.Colors.PRIMARY),
        title=ft.Text("Text Finder Mobile", size=18, weight=ft.FontWeight.BOLD),
        center_title=False,
        bgcolor=ft.Colors.SURFACE_CONTAINER_HIGH,
        actions=[theme_btn]
    )

    page.navigation_bar = nav_bar
    page.add(current_tab_container)


if __name__ == "__main__":
    if callable(getattr(ft, "run", None)):
        ft.run(main)
    elif callable(getattr(ft, "app", None)):
        ft.app(target=main)
    else:
        import flet.app as ft_app
        ft_app.run(main)
