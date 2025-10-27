import wx
import dns.resolver
import re
import subprocess
import ipaddress
import threading
import concurrent.futures

HOSTS_PATH = r'C:\Windows\System32\drivers\etc\hosts'
DONT_WORK = 0
MAX_WORKERS = 8
ATTEMPTS = 12
DNS_SERVERS = [
    'free.shecan.ir',
    'dns.electrotm.org',
    'dns.malw.link',
]

def get_shecan_dns():
    dns_ips = []
    for server in DNS_SERVERS:
        try:
            answers = dns.resolver.resolve(server, 'A')
            for answer in answers:
                dns_ips.append(answer.address)
        except Exception as e:
            wx.MessageBox(f"Ошибка при получении DNS {server}: {e}", "Ошибка")
    return dns_ips
    
def parse_hosts_lines():
    entries = []
    try:
        with open(HOSTS_PATH, 'r') as f:
            for line in f:
                original_line = line.rstrip('\n')
                match = re.match(r'^\s*(#)?\s*(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)', original_line)
                if match:
                    commented, ip, domain = match.groups()
                    active = not commented
                    entries.append((original_line, active, ip, domain))
        return entries
    except Exception:
        return []

def write_hosts_entries(entries):
    try:
        with open(HOSTS_PATH, 'w') as f:
            for line, active, ip, domain in entries:
                prefix = '' if active else '#'
                f.write(f"{prefix}{ip} {domain}\n")
        return True
    except Exception:
        return False

class MainFrame(wx.Frame):
    def __init__(self):
        super().__init__(None, title="Dyatel", size=(1000, 600))
        splitter = wx.SplitterWindow(self)
        left_panel = wx.Panel(splitter)
        right_panel = wx.Panel(splitter)

        self.hosts_list = wx.ListCtrl(left_panel, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.hosts_list.InsertColumn(0, "Статус", width=70)
        self.hosts_list.InsertColumn(1, "IP", width=150)
        self.hosts_list.InsertColumn(2, "Домен", width=200)

        self.sort_column = 0
        self.sort_ascending = True

        self.hosts_list.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.toggle_host_entry)
        self.hosts_list.Bind(wx.EVT_LIST_COL_CLICK, self.on_column_click)

        self.hosts_list.Bind(wx.EVT_LIST_ITEM_RIGHT_CLICK, self.on_right_click)

        left_sizer = wx.BoxSizer(wx.VERTICAL)
        left_sizer.Add(self.hosts_list, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
        left_panel.SetSizer(left_sizer)

        right_sizer = wx.BoxSizer(wx.VERTICAL)

        self.dns_entry = wx.ComboBox(right_panel, style=wx.CB_READONLY)
        right_sizer.Add(wx.StaticText(right_panel, label="DNS-адрес:"), flag=wx.LEFT | wx.TOP, border=5)
        right_sizer.Add(self.dns_entry, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=5)

        self.domain_entry = wx.TextCtrl(right_panel)
        right_sizer.Add(wx.StaticText(right_panel, label="Домен:"), flag=wx.LEFT | wx.TOP, border=5)
        right_sizer.Add(self.domain_entry, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=5)

        button_sizer = wx.BoxSizer(wx.HORIZONTAL)

        self.nslookup_btn = wx.Button(right_panel, label="nslookup")
        self.nslookup_btn.Bind(wx.EVT_BUTTON, self.on_nslookup)
        button_sizer.Add(self.nslookup_btn, 0, wx.ALL, 5)

        self.update_all_btn = wx.Button(right_panel, label="update all")
        self.update_all_btn.Bind(wx.EVT_BUTTON, self.on_update_all)
        button_sizer.Add(self.update_all_btn, 0, wx.ALL, 5)

        right_sizer.Add(button_sizer, 0, wx.ALIGN_CENTER_HORIZONTAL)


        self.result_box = wx.TextCtrl(right_panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        right_sizer.Add(wx.StaticText(right_panel, label="Результат nslookup:"), flag=wx.LEFT | wx.TOP, border=5)
        right_sizer.Add(self.result_box, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)

        self.ip_summary = wx.ComboBox(right_panel, style=wx.CB_READONLY)
        right_sizer.Add(wx.StaticText(right_panel, label="IP адреса:"), flag=wx.LEFT | wx.TOP, border=5)
        right_sizer.Add(self.ip_summary, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=5)

        self.add_btn = wx.Button(right_panel, label="Добавить в hosts")
        self.add_btn.Bind(wx.EVT_BUTTON, self.on_add_to_hosts)
        right_sizer.Add(self.add_btn, flag=wx.ALL | wx.ALIGN_CENTER, border=5)

        right_panel.SetSizer(right_sizer)
        splitter.SplitVertically(left_panel, right_panel, sashPosition=580)
        splitter.SetMinimumPaneSize(200)

        self.hosts_entries = parse_hosts_lines()
        self.load_hosts_table()
        self.load_dns()

    def load_hosts_table(self):
        v_scroll_pos = self.hosts_list.GetScrollPos(wx.VERTICAL)
        selected_index = self.hosts_list.GetFirstSelected()

        self.hosts_list.Freeze()
        self.hosts_list.DeleteAllItems()
        for idx, (line, active, ip, domain) in enumerate(self.hosts_entries):
            index = self.hosts_list.InsertItem(idx, "✅" if active else "❌")
            self.hosts_list.SetItem(index, 1, ip)
            self.hosts_list.SetItem(index, 2, domain)
        self.hosts_list.Thaw()

        if 0 <= selected_index < self.hosts_list.GetItemCount():
            self.hosts_list.Select(selected_index)

        wx.CallAfter(lambda: self.hosts_list.ScrollLines(v_scroll_pos))


    def on_column_click(self, event):
        col = event.GetColumn()
        if col == self.sort_column:
            self.sort_ascending = not self.sort_ascending
        else:
            self.sort_column = col
            self.sort_ascending = True

        key_funcs = [
            lambda x: x[1],
            lambda x: x[2],
            lambda x: x[3],
        ]
        key_func = key_funcs[col]
        self.hosts_entries = sorted(self.hosts_entries, key=key_func, reverse=not self.sort_ascending)
        self.load_hosts_table()

    def load_dns(self):
        dns_ips = get_shecan_dns()
        if dns_ips:
            self.dns_entry.Clear()
            self.dns_entry.AppendItems(dns_ips)
            self.dns_entry.SetSelection(0)
        else:
            self.dns_entry.Clear()
            self.dns_entry.Append("Ошибка получения DNS")

    def on_nslookup(self, event):
        dns = self.dns_entry.GetValue().strip()
        domain = self.domain_entry.GetValue().strip()

        if not domain:
            wx.MessageBox("Введите домен для проверки", "Ошибка")
            return

        try:
            ipaddress.ip_address(dns)
        except ValueError:
            wx.MessageBox("Введённый DNS-адрес некорректен", "Ошибка")
            return

        self.result_box.SetValue("Выполняется nslookup...")
        self.ip_summary.Clear()

        thread = threading.Thread(target=self.run_nslookup_threaded, args=(domain, dns))
        thread.start()

    def on_update_all(self, event):
        dns = self.dns_entry.GetValue().strip()

        try:
            ipaddress.ip_address(dns)
        except ValueError:
            wx.MessageBox("Введённый DNS-адрес некорректен", "Ошибка")
            return

        updated_entries = []
        results = []

        self.result_box.SetValue("Выполняется массовое обновление...\n")

        def update_all_thread():
            nonlocal results

            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [
                    executor.submit(self.update_host_entry, domain, dns, results)
                    for _, active, ip, domain in self.hosts_entries
                    if active and ip != '0.0.0.0'
                ]

            concurrent.futures.wait(futures)

            for line, active, ip, domain in self.hosts_entries:
                if active:
                    found = False
                    for result in results:
                        if result['domain'] == domain:
                            new_ip = result['ip']
                            if new_ip is not None:
                                updated_entries.append((f"{new_ip} {domain}", True, new_ip, domain))
                                found = True
                                break
                    if not found:
                        updated_entries.append((line, active, ip, domain))
                else:
                    updated_entries.append((line, active, ip, domain))

            # for line, active, ip, domain in self.hosts_entries:
                # if ip == '0.0.0.0':
                    # updated_entries.append((line, active, ip, domain))

            if write_hosts_entries(updated_entries):
                wx.CallAfter(self.hosts_entries.__setitem__, slice(None), updated_entries)
                wx.CallAfter(self.load_hosts_table)
                wx.CallAfter(subprocess.run, ["ipconfig", "/flushdns"], shell=True)
                wx.CallAfter(wx.MessageBox, "Обновление записей завершено!", "Успех")
                wx.CallAfter(self.result_box.AppendText, f" Не удалось обработать {DONT_WORK} доменов\n")
        threading.Thread(target=update_all_thread, daemon=True).start()

    def update_host_entry(self, domain, dns, results):
        attempts = ATTEMPTS
        while attempts != -1 and attempts != 0:
            try:
                result = subprocess.run(
                    ['nslookup', domain, dns],
                    capture_output=True,
                    text=True,
                    shell=True,
                    timeout=5
                )

                output = result.stdout
                ip_list = re.findall(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)', output.replace(dns, ''))

                if ip_list:
                    results.append({
                        'domain': domain,
                        'ip': ip_list[0]
                    })
                    wx.CallAfter(self.result_box.AppendText, f"Домен {domain} -> {ip_list[0]}\n")
                    attempts = -1
                else:
                    results.append({
                        'domain': domain,
                        'ip': None
                    })
                    wx.CallAfter(self.result_box.AppendText, f"Домен {domain}: IP не найден\n")
                    wx.CallAfter(self.result_box.AppendText, f" Осталось попыток обработать {domain}: {attempts}\n")
                    attempts -= 1

            except Exception as e:
                wx.CallAfter(self.result_box.AppendText, f"Ошибка при обработке {domain}: {str(e)}\n")
                wx.CallAfter(self.result_box.AppendText, f" Осталось попыток обработать {domain}: {attempts}\n")
                attempts -= 1
        
        if attempts == 0:
            global DONT_WORK
            DONT_WORK += 1

    def run_nslookup_threaded(self, domain, dns):
        try:
            result = subprocess.run(
                ['nslookup', domain, dns],
                capture_output=True, text=True, shell=True
            )

            output = result.stdout
            ip_list = re.findall(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)', output.replace(dns, ''))

            wx.CallAfter(self.result_box.SetValue, output)
            wx.CallAfter(self.ip_summary.Clear)
            if ip_list:
                wx.CallAfter(self.ip_summary.AppendItems, ip_list)
                wx.CallAfter(self.ip_summary.SetSelection, 0)
            else:
                wx.CallAfter(self.ip_summary.Append, "IP не найден")
                wx.CallAfter(self.ip_summary.SetSelection, 0)

        except Exception as e:
            wx.CallAfter(self.result_box.SetValue, f"Ошибка: {e}")
            wx.CallAfter(self.ip_summary.Clear)

    def on_add_to_hosts(self, event):
        domain = self.domain_entry.GetValue().strip()
        ip = self.ip_summary.GetValue().strip()

        if not domain or not ip or "не найден" in ip.lower():
            return

        entries = parse_hosts_lines()
        updated = False
        found = False

        for i, (orig, active, entry_ip, entry_domain) in enumerate(entries):
            if entry_domain == domain:
                found = True
                dlg = wx.MessageDialog(self, f"Запись для {domain} уже существует.\nЗаменить?", "Подтверждение", wx.YES_NO)
                if dlg.ShowModal() == wx.ID_YES:
                    entries[i] = (f"{ip} {domain}", True, ip, domain)
                    updated = True
                dlg.Destroy()
                break

        if not found:
            entries.append((f"{ip} {domain}", True, ip, domain))
            updated = True

        if updated:
            if write_hosts_entries(entries):
                self.hosts_entries = entries
                self.load_hosts_table()
                subprocess.run(["ipconfig", "/flushdns"], shell=True)
                wx.MessageBox("Запись добавлена или обновлена!", "Успех")




    def toggle_host_entry(self, event):
        index = event.GetIndex()
        line, active, ip, domain = self.hosts_entries[index]
        self.hosts_entries[index] = (f"{ip} {domain}", not active, ip, domain)
        if write_hosts_entries(self.hosts_entries):
            self.load_hosts_table()

    def on_right_click(self, event):
        index = event.GetIndex()
        if index == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        toggle_item = menu.Append(wx.ID_ANY, "Вкл/выкл")
        copy_item = menu.Append(wx.ID_ANY, "Копировать строку")
        delete_item = menu.Append(wx.ID_ANY, "Удалить запись")

        self.Bind(wx.EVT_MENU, lambda e: self.context_toggle(index), toggle_item)
        self.Bind(wx.EVT_MENU, lambda e: self.context_copy(index), copy_item)
        self.Bind(wx.EVT_MENU, lambda e: self.context_delete(index), delete_item)

        self.PopupMenu(menu)
        menu.Destroy()

    def context_toggle(self, index):
        line, active, ip, domain = self.hosts_entries[index]
        self.hosts_entries[index] = (f"{ip} {domain}", not active, ip, domain)
        if write_hosts_entries(self.hosts_entries):
            self.load_hosts_table()

    def context_copy(self, index):
        _, _, ip, domain = self.hosts_entries[index]
        text = f"{ip} {domain}"
        if wx.TheClipboard.Open():
            wx.TheClipboard.SetData(wx.TextDataObject(text))
            wx.TheClipboard.Close()
            wx.MessageBox("Строка скопирована в буфер обмена", "Копирование")

    def context_delete(self, index):
        dlg = wx.MessageDialog(self, "Удалить запись?", "Подтверждение", wx.YES_NO | wx.NO_DEFAULT | wx.ICON_WARNING)
        if dlg.ShowModal() == wx.ID_YES:
            del self.hosts_entries[index]
            if write_hosts_entries(self.hosts_entries):
                self.load_hosts_table()
        dlg.Destroy()

if __name__ == "__main__":
    app = wx.App(False)
    frame = MainFrame()
    frame.Show()
    app.MainLoop()
