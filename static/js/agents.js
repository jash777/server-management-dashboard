// static/js/agents.js
document.addEventListener('DOMContentLoaded', function() {
    const addAgentBtn = document.getElementById('add-agent-btn');
    const addAgentModal = document.getElementById('add-agent-modal');
    const addAgentForm = document.getElementById('add-agent-form');

    addAgentBtn.addEventListener('click', () => {
        addAgentModal.style.display = 'block';
    });

    addAgentForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const name = document.getElementById('agent-name').value;
        const ipAddress = document.getElementById('agent-ip').value;
        addAgent(name, ipAddress);
    });

    window.onclick = (event) => {
        if (event.target == addAgentModal) {
            addAgentModal.style.display = 'none';
        }
    };
});

function addAgent(name, ipAddress) {
    fetch('/api/agents', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name, ip_address: ipAddress }),
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
        location.reload();
    })
    .catch((error) => {
        console.error('Error:', error);
        alert('Error adding agent');
    });
}

function removeAgent(agentId) {
    if (confirm('Are you sure you want to remove this agent?')) {
        fetch(`/api/agents?id=${agentId}`, {
            method: 'DELETE',
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            location.reload();
        })
        .catch((error) => {
            console.error('Error:', error);
            alert('Error removing agent');
        });
    }
}

function checkAgentStatus(agentId) {
    fetch(`/api/check_agent_status/${agentId}`)
    .then(response => response.json())
    .then(data => {
        alert(`Agent status: ${data.status}`);
        location.reload();
    })
    .catch((error) => {
        console.error('Error:', error);
        alert('Error checking agent status');
    });
}