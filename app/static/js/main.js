document.addEventListener('DOMContentLoaded', function() {
    // Add any JavaScript functionality needed
    console.log('Caddy Web UI loaded');
    
    // Example: Confirm before reverting a version
    document.querySelectorAll('a[href*="revert"]').forEach(link => {
        link.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to revert to this version?')) {
                e.preventDefault();
            }
        });
    });
});