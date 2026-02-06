// Main JavaScript for Tarmoq Xavfsizligi Skaneri

// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Auto-hide alert messages after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert:not(.alert-important)');
        alerts.forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // Helper function to show alerts
    function showAlert(message, type) {
        const alertContainer = document.getElementById('alertContainer') || document.querySelector('.container:first-child');
        if (alertContainer) {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
            alertDiv.innerHTML = `
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            `;
            alertContainer.prepend(alertDiv);
            
            // Auto remove after 5 seconds
            setTimeout(() => {
                const bsAlert = new bootstrap.Alert(alertDiv);
                bsAlert.close();
            }, 5000);
        }
    }

    // AJAX live scan option (if scan button with id 'liveScanButton' exists)
    const liveScanButton = document.getElementById('liveScanButton');
    if (liveScanButton) {
        liveScanButton.addEventListener('click', function(event) {
            event.preventDefault();
            
            const target = document.getElementById('target').value;
            const scanType = document.querySelector('input[name="scan_type"]:checked').value;
            
            if (!target.trim()) {
                showAlert('Iltimos, skanerlash manzilini kiriting!', 'danger');
                return;
            }
            
            // Update button state
            liveScanButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Skanerlash jarayonda...';
            liveScanButton.disabled = true;
            
            // Show progress indication
            const resultContainer = document.getElementById('liveScanResults');
            if (resultContainer) {
                resultContainer.innerHTML = '<div class="text-center p-5"><div class="spinner-border text-primary" role="status"></div><p class="mt-3">Skanerlash jarayonda, iltimos kuting...</p></div>';
                resultContainer.style.display = 'block';
            }
            
            // Make AJAX request to the backend
            fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({
                    target: target,
                    scan_type: scanType
                })
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Skanerlash jarayonida xatolik yuz berdi');
                }
                return response.json();
            })
            .then(data => {
                // Display scan results
                if (resultContainer) {
                    // Format results based on scan type
                    let resultsHTML = formatScanResults(data, scanType);
                    resultContainer.innerHTML = resultsHTML;
                }
                
                // Reset button state
                liveScanButton.innerHTML = '<i class="fas fa-search"></i> Skanerlash';
                liveScanButton.disabled = false;
                
                // Show success message
                showAlert('Skanerlash muvaffaqiyatli yakunlandi!', 'success');
            })
            .catch(error => {
                console.error('Error:', error);
                
                // Reset button state
                liveScanButton.innerHTML = '<i class="fas fa-search"></i> Skanerlash';
                liveScanButton.disabled = false;
                
                // Show error message
                showAlert('Xatolik: ' + error.message, 'danger');
                
                if (resultContainer) {
                    resultContainer.innerHTML = '<div class="alert alert-danger">Skanerlash jarayonida xatolik yuz berdi. Iltimos, qaytadan urinib ko\'ring.</div>';
                }
            });
        });
    }

    // Format scan results based on scan type
    function formatScanResults(data, scanType) {
        let resultsHTML = '<div class="card shadow-sm">';
        resultsHTML += '<div class="card-header bg-light"><h5 class="mb-0">Skanerlash natijalari</h5></div>';
        resultsHTML += '<div class="card-body">';
        
        // Create different display based on scan type
        if (scanType === 'ports') {
            // Port scanning results
            if (data.results && data.results.length > 0) {
                resultsHTML += `<div class="alert alert-${data.severity === 'High' ? 'danger' : (data.severity === 'Medium' ? 'warning' : 'info')} mb-4">`;
                resultsHTML += `<i class="fas fa-info-circle me-2"></i><strong>${data.severity === 'High' ? 'Yuqori' : (data.severity === 'Medium' ? 'O\'rta' : 'Past')} xavf:</strong> `;
                
                if (data.severity === 'High') {
                    resultsHTML += 'Ko\'p sonli ochiq portlar aniqlandi. Bu tarmoq himoyasiga tahdid soladi.';
                } else if (data.severity === 'Medium') {
                    resultsHTML += 'Ba\'zi muhim portlar ochiq. Faqat zarur bo\'lgan portlarni ochiq qoldiring.';
                } else {
                    resultsHTML += 'Bir nechta standart portlar ochiq. Bu normal holat.';
                }
                
                resultsHTML += '</div>';
                
                resultsHTML += `<h5 class="mb-3">Ochiq portlar (${data.results.length})</h5>`;
                resultsHTML += '<div class="table-responsive"><table class="table table-striped">';
                resultsHTML += '<thead><tr><th>Port</th><th>Xizmat</th><th>Tavsiya</th></tr></thead>';
                resultsHTML += '<tbody>';
                
                data.results.forEach(port => {
                    let recommendation = '';
                    
                    if (port.port === 21) {
                        recommendation = 'FTP xizmati xavfsiz emas. SFTP yoki FTPs dan foydalaning.';
                    } else if (port.port === 23) {
                        recommendation = 'Telnet xavfsiz emas. SSH (22-port) dan foydalaning.';
                    } else if (port.port === 25) {
                        recommendation = 'SMTP portini himoyalash kerak.';
                    } else if (port.port === 80) {
                        recommendation = 'HTTP xavfsiz emas. HTTPS (443-port) dan foydalaning.';
                    } else if (port.port === 3389) {
                        recommendation = 'RDP portini himoyalashni kuchaytiring.';
                    } else {
                        recommendation = 'Agar zarurat bo\'lmasa, portni yoping.';
                    }
                    
                    resultsHTML += `<tr>
                        <td><strong>${port.port}</strong></td>
                        <td>${port.service}</td>
                        <td>${recommendation}</td>
                    </tr>`;
                });
                
                resultsHTML += '</tbody></table></div>';
            } else {
                resultsHTML += '<div class="alert alert-success"><i class="fas fa-check-circle me-2"></i><strong>Yaxshi!</strong> Tekshirilgan portlarda ochiq portlar topilmadi.</div>';
            }
        } else if (scanType === 'ssl') {
            // SSL certificate results
            if (data.results && !data.results.error) {
                resultsHTML += `<div class="alert alert-${data.severity === 'High' ? 'danger' : (data.severity === 'Medium' ? 'warning' : 'success')} mb-4">`;
                resultsHTML += `<i class="fas fa-info-circle me-2"></i>`;
                
                if (data.severity === 'High') {
                    resultsHTML += '<strong>Yuqori xavf:</strong> SSL sertifikat muddati tugagan!';
                } else if (data.severity === 'Medium') {
                    resultsHTML += `<strong>O'rta xavf:</strong> SSL sertifikat muddati yaqin kunlarda tugaydi (${data.results.days_left} kun qoldi).`;
                } else {
                    resultsHTML += '<strong>Past xavf:</strong> SSL sertifikat yaxshi holatda.';
                }
                
                resultsHTML += '</div>';
                
                resultsHTML += '<h5 class="mb-3">SSL Sertifikat ma\'lumotlari</h5>';
                resultsHTML += '<div class="table-responsive"><table class="table table-striped">';
                resultsHTML += '<tbody>';
                
                resultsHTML += `<tr>
                    <th style="width: 30%">Status:</th>
                    <td><span class="badge bg-${data.results.status === 'Valid' ? 'success' : 'danger'}">${data.results.status === 'Valid' ? 'Yaroqli' : 'Yaroqsiz'}</span></td>
                </tr>`;
                
                resultsHTML += `<tr>
                    <th>Qolgan muddat:</th>
                    <td>${data.results.days_left} kun</td>
                </tr>`;
                
                if (data.results.subject && data.results.subject.CN) {
                    resultsHTML += `<tr>
                        <th>Sertifikat egasi:</th>
                        <td>${data.results.subject.CN}</td>
                    </tr>`;
                }
                
                if (data.results.issuer && data.results.issuer.CN) {
                    resultsHTML += `<tr>
                        <th>Sertifikat beruvchi:</th>
                        <td>${data.results.issuer.CN}</td>
                    </tr>`;
                }
                
                resultsHTML += `<tr>
                    <th>Amal qilish boshlanishi:</th>
                    <td>${data.results.not_before}</td>
                </tr>`;
                
                resultsHTML += `<tr>
                    <th>Amal qilish tugashi:</th>
                    <td>${data.results.not_after}</td>
                </tr>`;
                
                resultsHTML += '</tbody></table></div>';
            } else {
                resultsHTML += `<div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    <strong>Xato:</strong> ${data.results.error || 'SSL sertifikatni tekshirishda xatolik yuz berdi'}
                </div>`;
            }
        } else if (scanType === 'headers') {
            // HTTP headers results
            if (data.results && !data.results.error) {
                resultsHTML += `<div class="alert alert-${data.severity === 'High' ? 'danger' : (data.severity === 'Medium' ? 'warning' : 'success')} mb-4">`;
                resultsHTML += `<i class="fas fa-info-circle me-2"></i>`;
                resultsHTML += `<strong>Xavfsizlik xolati:</strong> ${data.results.missing_count} xavfsizlik headerlari mavjud emas`;
                resultsHTML += '</div>';
                
                resultsHTML += '<h5 class="mb-3">HTTP Header ma\'lumotlari</h5>';
                resultsHTML += '<div class="table-responsive"><table class="table table-striped">';
                resultsHTML += '<thead><tr><th>Header</th><th>Qiymat</th><th>Status</th></tr></thead>';
                resultsHTML += '<tbody>';
                
                for (const [header, value] of Object.entries(data.results.headers)) {
                    resultsHTML += `<tr>
                        <td><strong>${header}</strong></td>
                        <td>${value}</td>
                        <td><span class="badge bg-${value === 'Missing' ? 'danger' : 'success'}">${value === 'Missing' ? 'Mavjud emas' : 'Mavjud'}</span></td>
                    </tr>`;
                }
                
                resultsHTML += '</tbody></table></div>';
            } else {
                resultsHTML += `<div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    <strong>Xato:</strong> ${data.results.error || 'HTTP headerlarni tekshirishda xatolik yuz berdi'}
                </div>`;
            }
        } else if (scanType === 'sql_injection' || scanType === 'xss') {
            // SQL injection or XSS results
            if (data.results && data.results.length > 0) {
                resultsHTML += `<div class="alert alert-danger mb-4">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    <strong>Yuqori xavf:</strong> ${scanType === 'sql_injection' ? 'SQL Injection' : 'XSS'} zaifliklari aniqlandi. Bu jiddiy xavfsizlik muammosidir.
                </div>`;
                
                resultsHTML += `<h5 class="mb-3">Aniqlangan ${scanType === 'sql_injection' ? 'SQL Injection' : 'XSS'} zaifliklari</h5>`;
                resultsHTML += '<div class="table-responsive"><table class="table table-striped">';
                resultsHTML += '<thead><tr><th>Payload</th><th>Tavsif</th><th>Xavf darajasi</th></tr></thead>';
                resultsHTML += '<tbody>';
                
                data.results.forEach(item => {
                    resultsHTML += `<tr>
                        <td><code>${item.payload}</code></td>
                        <td>${item.description}</td>
                        <td><span class="badge bg-danger">${item.severity}</span></td>
                    </tr>`;
                });
                
                resultsHTML += '</tbody></table></div>';
            } else {
                resultsHTML += `<div class="alert alert-success mb-4">
                    <i class="fas fa-check-circle me-2"></i>
                    <strong>Yaxshi!</strong> Hozircha ${scanType === 'sql_injection' ? 'SQL Injection' : 'XSS'} zaifliklari aniqlanmadi.
                </div>`;
            }
        }
        
        // End result card
        resultsHTML += '</div></div>';
        
        // Add recommendations section
        resultsHTML += '<div class="card shadow-sm mt-4">';
        resultsHTML += '<div class="card-header bg-light"><h5 class="mb-0">Xavfsizlik tavsiylari</h5></div>';
        resultsHTML += '<div class="card-body">';
        resultsHTML += '<ul class="list-group">';
        
        // Add recommendations based on scan type
        if (scanType === 'ports') {
            resultsHTML += `
                <li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i>Faqat zarur bo'lgan portlarni ochiq qoldiring va boshqalarini yoping.</li>
                <li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i>Firewall orqali ochiq portlarga kirishni cheklang.</li>
                <li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i>Xizmatlarni doimo yangilab turing va xavfsizlik yangilanishlarini o'rnating.</li>
            `;
        } else if (scanType === 'ssl') {
            if (data.severity === 'High') {
                resultsHTML += `<li class="list-group-item"><i class="fas fa-exclamation-triangle text-danger me-2"></i><strong>Zudlik bilan sertifikatni yangilang!</strong> Muddati tugagan sertifikat xavfsizlikni ta'minlamaydi.</li>`;
            } else if (data.severity === 'Medium') {
                resultsHTML += `<li class="list-group-item"><i class="fas fa-exclamation-circle text-warning me-2"></i><strong>Sertifikatni tez orada yangilang.</strong> Muddati tugashiga ${data.results.days_left} kun qoldi.</li>`;
            }
            
            resultsHTML += `
                <li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i>Sertifikatni yangilash jarayonini avtomatlashtirish uchun Let's Encrypt kabi xizmatlardan foydalaning.</li>
                <li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i>SSL sertifikatlarni muntazam tekshirib turing va eslatmalarni sozlang.</li>
            `;
        } else if (scanType === 'headers') {
            if (data.results && data.results.headers) {
                if (data.results.headers['Strict-Transport-Security'] === 'Missing') {
                    resultsHTML += `<li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i><strong>Strict-Transport-Security</strong> headerini qo'shing. Bu foydalanuvchilarni HTTPS protokolidan foydalanishga majbur qiladi.</li>`;
                }
                
                if (data.results.headers['Content-Security-Policy'] === 'Missing') {
                    resultsHTML += `<li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i><strong>Content-Security-Policy</strong> headerini qo'shing. Bu XSS hujumlaridan himoya qilishga yordam beradi.</li>`;
                }
                
                if (data.results.headers['X-Content-Type-Options'] === 'Missing') {
                    resultsHTML += `<li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i><strong>X-Content-Type-Options</strong> headerini qo'shing. Bu MIME type sniffing hujumlaridan himoya qilishga yordam beradi.</li>`;
                }
                
                if (data.results.headers['X-Frame-Options'] === 'Missing') {
                    resultsHTML += `<li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i><strong>X-Frame-Options</strong> headerini qo'shing. Bu clickjacking hujumlaridan himoya qilishga yordam beradi.</li>`;
                }
                
                if (data.results.headers['X-XSS-Protection'] === 'Missing') {
                    resultsHTML += `<li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i><strong>X-XSS-Protection</strong> headerini qo'shing. Bu XSS hujumlaridan himoya qilishga yordam beradi.</li>`;
                }
            }
        } else if (scanType === 'sql_injection') {
            resultsHTML += `
                <li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i><strong>Prepared statementsdan foydalaning.</strong> Bu SQL Injection hujumlarini oldini olishning eng yaxshi usulidir.</li>
                <li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i><strong>Kiritilgan ma'lumotlarni validatsiya qiling.</strong> Barcha foydalanuvchi kiritadigan ma'lumotlar tekshirilishi kerak.</li>
                <li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i><strong>Ma'lumotlar bazasi foydalanuvchisining huquqlarini cheklang.</strong> Ma'lumotlar bazasi foydalanuvchisiga faqat zarur bo'lgan minimal huquqlarni bering.</li>
                <li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i><strong>Web Application Firewall (WAF) o'rnating.</strong> Bu SQL Injection hujumlarini bloklashga yordam beradi.</li>
            `;
        } else if (scanType === 'xss') {
            resultsHTML += `
                <li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i><strong>Kiritilgan ma'lumotlarni validatsiya qiling va sanitizatsiya qiling.</strong> Barcha foydalanuvchi kiritadigan ma'lumotlar tekshirilishi va xavfsiz qilinishi kerak.</li>
                <li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i><strong>Content-Security-Policy headerini sozlang.</strong> Bu XSS hujumlarini oldini olishga yordam beradi.</li>
                <li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i><strong>HTTPOnly cookie flagini ishlatng.</strong> Bu client-side scriptlarni cookie ma'lumotlariga kirishini oldini oladi.</li>
                <li class="list-group-item"><i class="fas fa-shield-alt text-primary me-2"></i><strong>Web Application Firewall (WAF) o'rnating.</strong> Bu XSS hujumlarini bloklashga yordam beradi.</li>
            `;
        }
        
        resultsHTML += '</ul>';
        resultsHTML += '</div></div>';
        
        // Add save button
        resultsHTML += '<div class="d-grid gap-2 mt-4">';
        resultsHTML += `<button id="saveScanResults" class="btn btn-success" data-scan-data='${JSON.stringify(data)}'>
            <i class="fas fa-save"></i> Skanerlash natijasini saqlash
        </button>`;
        resultsHTML += '</div>';
        
        return resultsHTML;
    }

    // Save scan results to database
    document.addEventListener('click', function(e) {
        if (e.target && e.target.id === 'saveScanResults') {
            const scanData = JSON.parse(e.target.getAttribute('data-scan-data'));
            const target = document.getElementById('target').value;
            const scanType = document.querySelector('input[name="scan_type"]:checked').value;
            
            // Update button state
            e.target.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Saqlanmoqda...';
            e.target.disabled = true;
            
            // Save results to database
            fetch('/api/save_scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({
                    target: target,
                    scan_type: scanType,
                    results: scanData.results,
                    severity: scanData.severity
                })
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Natijalarni saqlashda xatolik yuz berdi');
                }
                return response.json();
            })
            .then(data => {
                // Reset button state
                e.target.innerHTML = '<i class="fas fa-save"></i> Skanerlash natijasini saqlash';
                e.target.disabled = false;
                
                // Show success message
                showAlert('Skanerlash natijalari muvaffaqiyatli saqlandi!', 'success');
                
                // Redirect to scan results page if scan_id is provided
                if (data.scan_id) {
                    window.location.href = '/scan_results/' + data.scan_id;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                
                // Reset button state
                e.target.innerHTML = '<i class="fas fa-save"></i> Skanerlash natijasini saqlash';
                e.target.disabled = false;
                
                // Show error message
                showAlert('Xatolik: ' + error.message, 'danger');
            });
        }
    });

    // Delete multiple scan records
    const deleteSelectedButton = document.getElementById('deleteSelectedScans');
    if (deleteSelectedButton) {
        deleteSelectedButton.addEventListener('click', function() {
            const checkboxes = document.querySelectorAll('input[name="selectedScans"]:checked');
            if (checkboxes.length === 0) {
                showAlert('Iltimos, o\'chirilishi kerak bo\'lgan natijalarni tanlang', 'warning');
                return;
            }
            
            if (!confirm('Rostdan ham tanlangan ' + checkboxes.length + ' ta natijani o\'chirmoqchimisiz?')) {
                return;
            }
            
            const scanIds = Array.from(checkboxes).map(cb => cb.value);
            
            // Update button state
            deleteSelectedButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> O\'chirilmoqda...';
            deleteSelectedButton.disabled = true;
            
            // Delete selected scans
            fetch('/api/delete_multiple_scans', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({
                    scan_ids: scanIds
                })
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Natijalarni o\'chirishda xatolik yuz berdi');
                }
                return response.json();
            })
            .then(data => {
                // Show success message
                showAlert('Tanlangan natijalar muvaffaqiyatli o\'chirildi!', 'success');
                
                // Remove deleted rows
                scanIds.forEach(id => {
                    const row = document.getElementById('scan-row-' + id);
                    if (row) {
                        row.remove();
                    }
                });
                
                // Reset button state
                deleteSelectedButton.innerHTML = '<i class="fas fa-trash"></i> Tanlanganni o\'chirish';
                deleteSelectedButton.disabled = false;
                
                // Update select all checkbox
                const selectAllCheckbox = document.getElementById('selectAllScans');
                if (selectAllCheckbox) {
                    selectAllCheckbox.checked = false;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                
                // Reset button state
                deleteSelectedButton.innerHTML = '<i class="fas fa-trash"></i> Tanlanganni o\'chirish';
                deleteSelectedButton.disabled = false;
                
                // Show error message
                showAlert('Xatolik: ' + error.message, 'danger');
            });
        });
    }

    // Select all scans in history table
    const selectAllCheckbox = document.getElementById('selectAllScans');
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', function() {
            const checkboxes = document.querySelectorAll('input[name="selectedScans"]');
            checkboxes.forEach(cb => {
                cb.checked = selectAllCheckbox.checked;
            });
        });
    }

    // // AJAX dashboard statistics refresh
    // const refreshStatsButton = document.getElementById('refreshStats');
    // if (refreshStatsButton) {
    //     refreshStatsButton.addEventListener('click', function() {
    //         // Update button state
    //         refreshStatsButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
    //         refreshStatsButton.disabled = true;
            
    //         // Fetch dashboard statistics
    //         fetch('/api/dashboard_stats', {
    //             method: 'GET',
    //             headers: {
    //                 'X-Requested-With': 'XMLHttpRequest'
    //             }
    //         })
    //         .then(response => {
    //             if (!response.ok) {
    //                 throw new Error('Statistikani yangilashda xatolik yuz berdi');
    //             }
    //             return response.json();
    //         })
    //         .then(data => {
    //             // Update stats cards
    //             document.getElementById('totalScansCount').textContent = data.total_scans;
    //             document.getElementById('highRiskCount').textContent = data.high_risk_scans;
    //             document.getElementById('recentScansCount').textContent = data.recent_scans;
                
    //             // Reset button state
    //             refreshStatsButton.innerHTML = '<i class="fas fa-sync-alt"></i>';
    //             refreshStatsButton.disabled = false;
                
    //             // Show success message
    //             showAlert('Statistika yangilandi!', 'success');
                
    //             // Update recent scans table if available
    //             if (data.recent_scans_data && data.recent_scans_data.length > 0) {
    //                 const recentScansTableBody = document.getElementById('recentScansTableBody');
    //                 if (recentScansTableBody) {
    //                     recentScansTableBody.innerHTML = '';
                        
    //                     data.recent_scans_data.forEach(scan => {
    //                         let scanTypeBadge = '';
    //                         if (scan.scan_type === 'ports') {
    //                             scanTypeBadge = '<span class="badge bg-primary">Port skanerlash</span>';
    //                         } else if (scan.scan_type === 'ssl') {
    //                             scanTypeBadge = '<span class="badge bg-info">SSL Sertifikat</span>';
    //                         } else if (scan.scan_type === 'sql_injection') {
    //                             scanTypeBadge = '<span class="badge bg-warning">SQL Injection