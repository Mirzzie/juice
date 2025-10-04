FROM bkimminich/juice-shop:latest

# Install dd-trace for Node.js APM and IAST
RUN npm install --no-save dd-trace@latest

# Create startup script that loads dd-trace
RUN echo 'node -r dd-trace/init app.js' > /start.sh

CMD ["/start.sh"]