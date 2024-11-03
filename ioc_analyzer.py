import asyncio
import aiohttp
import tkinter as tk
from tkinter import messagebox, ttk
import re
import datetime
from config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, ALIENVAULT_API_KEY
import os

# === Функции валидации ===

def validate_ip(ip):
    pattern = re.compile(
        r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    )
    return pattern.match(ip)

def validate_hash(hash_value):
    pattern = re.compile(r"^[a-fA-F0-9]{32,64}$")
    return pattern.match(hash_value)

# === Асинхронные функции для запросов к API ===

async def query_abuseipdb(session, ip_address):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    try:
        async with session.get(url, headers=headers, params=params) as resp:
            if resp.status == 200:
                data = await resp.json()
                return {'type': 'abuseipdb', 'ioc': ip_address, 'data': data}
            else:
                error_text = await resp.text()
                print(f"VirusTotal response error: {error_text}")
                return {'type': 'abuseipdb', 'ioc': ip_address, 'error': f'Error {resp.status}: {error_text}'}
    except Exception as e:
        return {'type': 'abuseipdb', 'ioc': ip_address, 'error': str(e)}

async def query_virustotal_hash(session, hash_value):
    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    try:
        async with session.get(url, headers=headers) as resp:
            print(f"Querying VirusTotal for hash: {hash_value}")
            if resp.status == 200:
                data = await resp.json()
                return {'type': 'virustotal', 'ioc': hash_value, 'data': data}
            else:
                error_text = await resp.text()
                return {'type': 'virustotal', 'ioc': hash_value, 'error': f'Error {resp.status}: {error_text}'}
    except Exception as e:
        return {'type': 'virustotal', 'ioc': hash_value, 'error': str(e)}

async def query_alienvault(session, ioc_value):
    if validate_ip(ioc_value):
        indicator_type = 'IPv4'
    else:
        indicator_type = 'FileHash-SHA256' if len(ioc_value) == 64 else 'FileHash-MD5'
    url = f'https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{ioc_value}/general'
    headers = {
        'X-OTX-API-KEY': ALIENVAULT_API_KEY
    }
    try:
        async with session.get(url, headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                return {'type': 'alienvault', 'ioc': ioc_value, 'data': data}
            else:
                error_text = await resp.text()
                return {'type': 'alienvault', 'ioc': ioc_value, 'error': f'Error {resp.status}: {error_text}'}
    except Exception as e:
        return {'type': 'alienvault', 'ioc': ioc_value, 'error': str(e)}

async def analyze_iocs(ioc_list, update_progress):
    async with aiohttp.ClientSession() as session:
        tasks = []
        total_tasks = 0
        for ioc in ioc_list:
            if validate_ip(ioc):
                tasks.append(query_abuseipdb(session, ioc))
                total_tasks += 1
            if validate_hash(ioc):
                tasks.append(query_virustotal_hash(session, ioc))
                total_tasks += 1
            # Запрос к AlienVault для всех типов IOC
            tasks.append(query_alienvault(session, ioc))
            total_tasks += 1

        results = []
        completed = 0
        for f in asyncio.as_completed(tasks):
            result = await f
            results.append(result)
            completed += 1
            update_progress(completed, total_tasks)
        return results

# === Функция для расчёта скоринга и генерации подробного отчёта ===

def calculate_scores(results):
    scored_results = []
    ioc_dict = {}

    for result in results:
        ioc = result['ioc']
        if ioc not in ioc_dict:
            ioc_dict[ioc] = {'ioc': ioc, 'score': 0, 'details': '', 'types': [], 'data': {}}

        if 'error' in result:
            ioc_dict[ioc]['details'] += f"{result['type']} Error: {result['error']}\n"
            continue

        data = result.get('data', {})
        ioc_dict[ioc]['types'].append(result['type'])
        ioc_dict[ioc]['data'][result['type']] = data  # Сохраняем полные данные для отчёта

        # Расчёт score
        if result['type'] == 'abuseipdb':
            abuse_confidence = data['data'].get('abuseConfidenceScore', 0)
            ioc_dict[ioc]['score'] += abuse_confidence  # Весовой коэффициент 1
            ioc_dict[ioc]['details'] += f"AbuseIPDB Confidence Score: {abuse_confidence}\n"

        elif result['type'] == 'virustotal':
            attributes = data.get('data', {}).get('attributes', {})
            positives = attributes.get('last_analysis_stats', {}).get('malicious', 0)
            ioc_dict[ioc]['score'] += positives * 10  # Весовой коэффициент 10
            ioc_dict[ioc]['details'] += f"VirusTotal Malicious Detections: {positives}\n"

        elif result['type'] == 'alienvault':
            pulse_info = data.get('pulse_info', {})
            count = len(pulse_info.get('pulses', []))
            ioc_dict[ioc]['score'] += count * 5  # Весовой коэффициент 5
            ioc_dict[ioc]['details'] += f"AlienVault Pulses: {count}\n"

    # Преобразуем словарь в список
    for ioc_data in ioc_dict.values():
        scored_results.append(ioc_data)

    # Сортировка по убыванию критичности
    scored_results.sort(key=lambda x: x['score'], reverse=True)
    return scored_results

# === Функция для форматирования данных из API ===

def format_api_data(api_type, data):
    lines = []
    if api_type == 'abuseipdb':
        ip_data = data.get('data', {})
        lines.append(f"IP: {ip_data.get('ipAddress', '')}")
        lines.append(f"Количество жалоб: {ip_data.get('totalReports', '')}")
        lines.append(f"Уровень доверия злоупотреблений: {ip_data.get('abuseConfidenceScore', '')}")
        lines.append(f"Страна: {ip_data.get('countryCode', '')}")
        lines.append(f"Последнее сообщение: {ip_data.get('lastReportedAt', '')}")

    elif api_type == 'virustotal':
        attributes = data.get('data', {}).get('attributes', {})
        lines.append(f"MD5: {attributes.get('md5', '')}")
        lines.append(f"SHA1: {attributes.get('sha1', '')}")
        lines.append(f"SHA256: {attributes.get('sha256', '')}")
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        lines.append("Статистика последнего анализа:")
        for key, value in last_analysis_stats.items():
            lines.append(f"  {key.capitalize()}: {value}")
        lines.append("Детекторы, обнаружившие угрозу:")
        last_analysis_results = attributes.get('last_analysis_results', {})
        for engine, result in last_analysis_results.items():
            if result.get('category') == 'malicious':
                lines.append(f"  {engine}: {result.get('result')}")

    elif api_type == 'alienvault':
        pulse_info = data.get('pulse_info', {})
        pulses = pulse_info.get('pulses', [])
        lines.append(f"Количество пульсов: {len(pulses)}")
        for pulse in pulses:
            lines.append(f"Название пульса: {pulse.get('name', '')}")
            lines.append(f"Автор: {pulse.get('author_name', '')}")
            lines.append(f"Описание: {pulse.get('description', '')}")
            lines.append("—" * 20)

    return '\n'.join(lines)

# === Функция для генерации подробного HTML отчёта ===

def generate_report(results):
    report_name = f"IOC_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(report_name, 'w', encoding='utf-8') as report:
        report.write("<html><head><title>Отчёт об анализе IOC</title></head><body>")
        report.write("<h1>Отчёт об анализе IOC</h1>")
        report.write(f"<p>Дата генерации: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")

        for result in results:
            report.write(f"<h2>IOC: {result['ioc']}</h2>")
            report.write(f"<p><b>Критичность:</b> {result['score']}</p>")

            for api_type, api_data in result['data'].items():
                report.write(f"<h3>Данные из {api_type.capitalize()}:</h3>")
                formatted_data = format_api_data(api_type, api_data).replace('\n', '<br>')
                report.write(f"<p>{formatted_data}</p>")

        report.write("</body></html>")

    messagebox.showinfo("Отчёт сгенерирован", f"Отчёт сохранён как {report_name}")

# === Класс приложения с GUI ===

class IOCAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IOC Analyzer")

        # Поле ввода
        self.input_label = tk.Label(root, text="Введите IOC (по одному в каждой строке):")
        self.input_label.pack(pady=5)
        self.input_text = tk.Text(root, height=15, width=80)
        self.input_text.pack()

        # Кнопка "Анализировать"
        self.analyze_button = tk.Button(root, text="Анализировать", command=self.start_analysis)
        self.analyze_button.pack(pady=10)

        # Прогресс-бар
        self.progress = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=400, mode='determinate')
        self.progress.pack()

        # Treeview для отображения результатов
        self.result_tree = ttk.Treeview(root, columns=('IOC', 'Type', 'Score', 'Details'), show='headings')
        self.result_tree.heading('IOC', text='IOC')
        self.result_tree.heading('Type', text='Типы')
        self.result_tree.heading('Score', text='Критичность')
        self.result_tree.heading('Details', text='Детали')
        self.result_tree.column('IOC', width=150)
        self.result_tree.column('Type', width=100)
        self.result_tree.column('Score', width=80)
        self.result_tree.column('Details', width=400)
        self.result_tree.pack(fill='both', expand=True)

        # Кнопка "Сгенерировать отчёт"
        self.generate_report_button = tk.Button(root, text="Сгенерировать отчёт", command=self.generate_report)
        self.generate_report_button.pack(pady=10)

        self.results = []
        self.scored_results = []

    def update_progress(self, current, total):
        self.progress['value'] = (current / total) * 100
        self.root.update_idletasks()

    def start_analysis(self):
        ioc_input = self.input_text.get("1.0", tk.END).strip()
        ioc_list = [ioc.strip() for ioc in ioc_input.split('\n') if ioc.strip()]
        if not ioc_list:
            messagebox.showwarning("Нет данных", "Пожалуйста, введите хотя бы один IOC для анализа.")
            return
        self.progress['value'] = 0
        self.root.update_idletasks()
        self.analyze_button.config(state='disabled')
        self.root.update_idletasks()

        # Запуск асинхронного анализа
        try:
            self.results = asyncio.run(analyze_iocs(ioc_list, self.update_progress))
            self.scored_results = calculate_scores(self.results)

            # Обновление Treeview с результатами
            for item in self.result_tree.get_children():
                self.result_tree.delete(item)
            for result in self.scored_results:
                self.result_tree.insert('', 'end', values=(
                    result['ioc'],
                    ', '.join(result['types']),
                    result['score'],
                    result['details']
                ))
            messagebox.showinfo("Анализ завершён", "Анализ IOC завершён!")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
        finally:
            self.analyze_button.config(state='normal')

    def generate_report(self):
        if not self.scored_results:
            messagebox.showwarning("Нет данных", "Пожалуйста, выполните анализ перед генерацией отчёта.")
            return
        generate_report(self.scored_results)

# === Запуск приложения ===

if __name__ == '__main__':
    root = tk.Tk()
    app = IOCAnalyzerApp(root)
    root.mainloop()
