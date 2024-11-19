# house-services-prj

### Instructions to run via Docker

1. Build the Docker image:
    ```sh
    docker build -t house-services-prj .
    ```

2. Run the Docker container:
    ```sh
    docker run -p 5001:5001 house-services-prj
    ```

### Instructions to run locally

1. Create a virtual environment:
    ```sh
    python -m venv venv
    ```

2. Activate the virtual environment:

    - On Windows:
        ```sh
        .\venv\Scripts\activate
        ```
    - On macOS and Linux:
        ```sh
        source venv/bin/activate
        ```

3. Install the required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

### Running Locally

1. Ensure the virtual environment is activated.

2. Run the application:
    ```sh
    python -m flask run --host=0.0.0.0 --port=5001
    ```