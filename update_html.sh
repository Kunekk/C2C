#!/bin/bash
for file in /opt/C2C/templates/*.html; do
    sed -i '/<body>/a <button class="sidebar-toggle" onclick="toggleSidebar()">☰</button>' "$file"
done