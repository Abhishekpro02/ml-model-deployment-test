import logging

def setup_logging():
    """Configure logging for the application."""
    logging.basicConfig(
        level=logging.INFO,  # You can adjust this to DEBUG or ERROR based on the environment
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),  # Logs to the console
            logging.FileHandler("app.log", mode='a')  # Logs to a file
        ]
    )
    logging.info("Logging is set up.")