// static/js/dashboard.js

document.addEventListener('DOMContentLoaded', function() {
    // Port skanerlash formasi
    const portScanForm = document.getElementById('port-scan-form');
    const portScanLoader = document.getElementById('port-scan-loader');
    const portScanResults = document.getElementById('port-scan-results-container');
    
    // Zaiflik skanerlash formasi
    const vulnerabilityScanForm = document.getElementById('vulnerability-scan-form');
    const vulnerabilityScanLoader = document.getElementById('vulnerability-scan-loader');
    const vulnerabilityScanResults = document.getElementById('vulnerability-scan-results-container');
    
    // Trafik tahlili formasi
    const trafficAnalysisForm = document.getElementById('traffic-analysis-form');
    const trafficAnalysisLoader = document.getElementById('traffic-analysis-loader');
    const trafficAnalysisResults = document.getElementById('traffic-analysis-results-container');
    
    // Hisobot yaratish tugmasi
    const generateReportBtn = document.getElementById('generate-report');
    const reportLoader = document.getElementById('report-loader');
    const reportContent = document.getElementById('report-content');
    
    // Port skanerlash formasini yuborish
    if (portScanForm) {
        portScanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const target = document.getElementById('port-scan-target').value;
            const portRange = document.getElementById('port-scan-range').value;
            
            // Formani tekshirish
            if (!target) {
                alert('Manzilni kiriting');
                return;
            }
            
            // Loading ko'rsatish
            portScanLoader.style.display = 'flex';
            portScanResults.style.display = 'none';
            
            // So'rovni yuborish
            fetch('/api/scan/ports', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    target: target,
                    port_range: portRange
                })
            })
            .then(response => response.json())
            .then(data => {
                // Loading yashirish
                portScanLoader.style.display = 'none';
                
                if (data.success) {
                    // Natijalarni ko'rsatish
                    const resultTarget = document.getElementById('port-scan-result-target');
                    const resultTime = document.getElementById('port-scan-result-time');
                    const resultCount = document.getElementById('port-scan-result-count');
                    const resultTable = document.getElementById('port-scan-result-table');
                    
                    resultTarget.textContent = target;
                    resultTime.textContent = data.scan_time.toFixed(2);
                    resultCount.textContent = data.results.length;
                    
                    // Jadval hosil qilish
                    resultTable.innerHTML = '';
                    data.results.forEach(port => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${port.port}</td>
                            <td>${port.service || '-'}</td>
                            <td>${port.version || '-'}</td>
                            <td>${port.state}</td>
                        `;
                        resultTable.appendChild(row);
                    });
                    
                    // Statistikani yangilash
                    updateStats();
                    
                    // Natijalarni ko'rsatish
                    portScanResults.style.display = 'block';
                } else {
                    alert('Skanerlashda xatolik: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error scanning ports:', error);
                portScanLoader.style.display = 'none';
                alert('Skanerlashda xatolik yuz berdi');
            });
        });
    }
    
    // Zaiflik skanerlash formasini yuborish
    if (vulnerabilityScanForm) {
        vulnerabilityScanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const target = document.getElementById('vulnerability-scan-target').value;
            
            // Formani tekshirish
            if (!target) {
                alert('Manzilni kiriting');
                return;
            }
            
            // Loading ko'rsatish
            vulnerabilityScanLoader.style.display = 'flex';
            vulnerabilityScanResults.style.display = 'none';
            
            // So'rovni yuborish
            fetch('/api/scan/vulnerabilities', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    target: target
                })
            })
            .then(response => response.json())
            .then(data => {
                // Loading yashirish
                vulnerabilityScanLoader.style.display = 'none';
                
                if (data.success) {
                    // Natijalarni ko'rsatish
                    const resultTarget = document.getElementById('vulnerability-scan-result-target');
                    const vulnerabilityList = document.getElementById('vulnerability-list');
                    
                    resultTarget.textContent = data.target;
                    
                    // Zaifliklar ro'yxatini hosil qilish
                    vulnerabilityList.innerHTML = '';
                    
                    if (data.results.length === 0) {
                        vulnerabilityList.innerHTML = '<p>Zaifliklar aniqlanmadi</p>';
                    } else {
                        data.results.forEach(vuln => {
                            const item = document.createElement('div');
                            item.className = `vulnerability-item ${vuln.severity || 'info'}`;
                            
                            item.innerHTML = `
                                <div class="vulnerability-header">
                                    <div class="vulnerability-name">${vuln.name}</div>
                                    <div class="vulnerability-severity ${vuln.severity || 'info'}">${vuln.severity || 'info'}</div>
                                </div>
                                <div class="vulnerability-description">${vuln.description}</div>
                            `;
                            
                            vulnerabilityList.appendChild(item);
                        });
                    }
                    
                    // Statistikani yangilash
                    updateStats();
                    
                    // Natijalarni ko'rsatish
                    vulnerabilityScanResults.style.display = 'block';
                } else {
                    alert('Skanerlashda xatolik: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error scanning vulnerabilities:', error);
                vulnerabilityScanLoader.style.display = 'none';
                alert('Skanerlashda xatolik yuz berdi');
            });
        });
    }
    
    // Trafik tahlili formasini yuborish
    if (trafficAnalysisForm) {
        trafficAnalysisForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const interface = document.getElementById('traffic-interface').value;
            const duration = document.getElementById('traffic-duration').value;
            
            // Formani tekshirish
            if (!interface) {
                alert('Interfeys nomini kiriting');
                return;
            }
            
            // Loading ko'rsatish
            trafficAnalysisLoader.style.display = 'flex';
            trafficAnalysisResults.style.display = 'none';
            
            // So'rovni yuborish
            fetch('/api/scan/traffic', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    interface: interface,
                    duration: duration
                })
            })
            .then(response => response.json())
            .then(data => {
                // Loading yashirish
                trafficAnalysisLoader.style.display = 'none';
                
                if (data.success) {
                    // Natijalarni ko'rsatish
                    const resultInterface = document.getElementById('traffic-result-interface');
                    const resultDuration = document.getElementById('traffic-result-duration');
                    const resultPackets = document.getElementById('traffic-result-packets');
                    
                    resultInterface.textContent = interface;
                    resultDuration.textContent = duration;
                    resultPackets.textContent = data.results.total_packets;
                    
                    // Grafiklarni yaratish
                    createTrafficCharts(data.results);
                    
                    // Statistikani yangilash
                    updateStats();
                    
                    // Natijalarni ko'rsatish
                    trafficAnalysisResults.style.display = 'block';
                } else {
                    alert('Tahlil qilishda xatolik: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error analyzing traffic:', error);
                trafficAnalysisLoader.style.display = 'none';
                alert('Tahlil qilishda xatolik yuz berdi');
            });
        });
    }
    
    // Hisobot yaratish funksiyasi
    if (generateReportBtn) {
        generateReportBtn.addEventListener('click', function() {
            const reportType = document.getElementById('report-type').value;
            const reportDateRange = document.getElementById('report-date-range').value;
            
            // Loading ko'rsatish
            reportLoader.style.display = 'flex';
            reportContent.style.display = 'none';
            
            // Hisobot davri matnini aniqlash
            let periodText = '';
            switch (reportDateRange) {
                case 'day':
                    periodText = 'Bugun';
                    break;
                case 'week':
                    periodText = 'So\'nggi hafta';
                    break;
                case 'month':
                    periodText = 'So\'nggi oy';
                    break;
                case 'year':
                    periodText = 'So\'nggi yil';
                    break;
            }
            
            // Simulatsiya uchun hisobotni to'ldirish
            setTimeout(() => {
                // Loading yashirish
                reportLoader.style.display = 'none';
                
                // Hisobot yaratilgan vaqtni ko'rsatish
                const now = new Date();
                const formattedDate = `${now.getDate().toString().padStart(2, '0')}.${(now.getMonth() + 1).toString().padStart(2, '0')}.${now.getFullYear()} ${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
                
                document.getElementById('report-period').textContent = periodText;
                document.getElementById('report-creation-time').textContent = formattedDate;
                
                // Hisobot statistikasini ko'rsatish
                document.getElementById('report-total-scans').textContent = '15';
                document.getElementById('report-total-vulnerabilities').textContent = '28';
                document.getElementById('report-high-vulnerabilities').textContent = '5';
                
                // Zaifliklar jadvalini to'ldirish
                const vulnTable = document.getElementById('report-vulnerability-table');
                vulnTable.innerHTML = '';
                
                // Test ma'lumotlarini qo'shish
                const testVulns = [
                    { name: 'SQL Injection', target: 'example.com', severity: 'high', date: '01.04.2025' },
                    { name: 'XSS (Cross-Site Scripting)', target: 'test.com', severity: 'high', date: '02.04.2025' },
                    { name: 'No HTTPS Redirect', target: 'example.com', severity: 'medium', date: '03.04.2025' },
                    { name: 'Missing Security Headers', target: 'demo.com', severity: 'medium', date: '04.04.2025' },
                    { name: 'Information Disclosure', target: 'example.org', severity: 'low', date: '05.04.2025' }
                ];
                
                testVulns.forEach(vuln => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${vuln.name}</td>
                        <td>${vuln.target}</td>
                        <td><span class="vulnerability-severity ${vuln.severity}">${vuln.severity}</span></td>
                        <td>${vuln.date}</td>
                    `;
                    vulnTable.appendChild(row);
                });
                
                // Grafiklarni yaratish
                createReportCharts();
                
                // Hisobotni ko'rsatish
                reportContent.style.display = 'block';
            }, 1500);
        });
    }
    
    // Hisobot grafiklarini yaratish
    function createReportCharts() {
        // Zaifliklar xavf darajasi bo'yicha grafik
        const severityCtx = document.getElementById('severity-chart');
        if (severityCtx) {
            // Eski grafikni tozalash
            if (window.severityChart) {
                window.severityChart.destroy();
            }
            
            // Test ma'lumotlari
            const severityData = {
                labels: ['Yuqori', 'O\'rta', 'Past', 'Info'],
                datasets: [{
                    data: [5, 12, 8, 3],
                    backgroundColor: [
                        'rgba(231, 76, 60, 0.7)',
                        'rgba(241, 196, 15, 0.7)',
                        'rgba(52, 152, 219, 0.7)',
                        'rgba(46, 204, 113, 0.7)'
                    ]
                }]
            };
            
            window.severityChart = new Chart(severityCtx, {
                type: 'pie',
                data: severityData,
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'right'
                        }
                    }
                }
            });
        }
        
        // Skanerlashlar turi bo'yicha grafik
        const scanTypesCtx = document.getElementById('scan-types-chart');
        if (scanTypesCtx) {
            // Eski grafikni tozalash
            if (window.scanTypesChart) {
                window.scanTypesChart.destroy();
            }
            
            // Test ma'lumotlari
            const scanTypesData = {
                labels: ['Port skanerlash', 'Zaiflik skanerlash', 'Trafik tahlili'],
                datasets: [{
                    data: [7, 5, 3],
                    backgroundColor: [
                        'rgba(52, 152, 219, 0.7)',
                        'rgba(231, 76, 60, 0.7)',
                        'rgba(46, 204, 113, 0.7)'
                    ]
                }]
            };
            
            window.scanTypesChart = new Chart(scanTypesCtx, {
                type: 'doughnut',
                data: scanTypesData,
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'right'
                        }
                    }
                }
            });
        }
    }
    
    // Statistikani yangilash funksiyasi
    function updateStats() {
        // Tarix ma'lumotlarini olish
        fetch('/api/history')
            .then(response => response.json())
            .then(data => {
                if (data.success && data.history) {
                    // Umumiy skanerlashlar sonini hisoblash
                    document.getElementById('total-scans').textContent = data.history.length;
                    
                    // Serverlar sonini hisoblash
                    const uniqueTargets = new Set();
                    data.history.forEach(item => {
                        if (item.target) {
                            uniqueTargets.add(item.target);
                        }
                    });
                    document.getElementById('total-servers').textContent = uniqueTargets.size;
                    
                    // Zaifliklar sonini hisoblash
                    let vulnerabilityCount = 0;
                    data.history.forEach(item => {
                        if (item.type === 'vulnerability_scan') {
                            // Bu erda har bir skan natijalari uchun serverga so'rov yuborish kerak
                            // Lekin hozircha o'rtacha qiymat ishlatamiz
                            vulnerabilityCount += 3;
                        }
                    });
                    document.getElementById('total-vulnerabilities').textContent = vulnerabilityCount;
                }
            })
            .catch(error => {
                console.error('Error updating stats:', error);
            });
    }
    
    // Trafik tahlili grafiklarini yaratish
    function createTrafficCharts(data) {
        // Protokollar grafigi
        const protocolsCtx = document.getElementById('protocols-chart');
        if (protocolsCtx && data.protocols) {
            // Eski grafikni tozalash
            if (window.protocolsChart) {
                window.protocolsChart.destroy();
            }
            
            const protocolLabels = Object.keys(data.protocols);
            const protocolData = Object.values(data.protocols);
            
            window.protocolsChart = new Chart(protocolsCtx, {
                type: 'pie',
                data: {
                    labels: protocolLabels,
                    datasets: [{
                        data: protocolData,
                        backgroundColor: [
                            'rgba(52, 152, 219, 0.7)',
                            'rgba(46, 204, 113, 0.7)',
                            'rgba(155, 89, 182, 0.7)',
                            'rgba(52, 73, 94, 0.7)',
                            'rgba(241, 196, 15, 0.7)',
                            'rgba(230, 126, 34, 0.7)',
                            'rgba(231, 76, 60, 0.7)'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'right'
                        }
                    }
                }
            });
        }
        
        // Manba IP manzillar grafigi
        const srcIpsCtx = document.getElementById('src-ips-chart');
        if (srcIpsCtx && data.src_ips) {
            // Eski grafikni tozalash
            if (window.srcIpsChart) {
                window.srcIpsChart.destroy();
            }
            
            // Top 10 IP manzillarni olish
            const sortedSrcIps = Object.entries(data.src_ips)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10);
            
            const srcIpLabels = sortedSrcIps.map(ip => ip[0]);
            const srcIpData = sortedSrcIps.map(ip => ip[1]);
            
            window.srcIpsChart = new Chart(srcIpsCtx, {
                type: 'bar',
                data: {
                    labels: srcIpLabels,
                    datasets: [{
                        label: 'Paketlar soni',
                        data: srcIpData,
                        backgroundColor: 'rgba(52, 152, 219, 0.5)',
                        borderColor: 'rgba(52, 152, 219, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
        
        // Boshqa grafiklar uchun kod...
    }
    
    // Statistikani yuklash
    updateStats();
});