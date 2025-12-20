"""
Vertex AI RAG Retrieval Tool with Full Document Support

This module extends the standard VertexAiRagRetrieval tool to support retrieving
full documents from Google Cloud Storage when RESULT_MODE is set to 'documents'.
"""

import logging
from typing import Any, List, Optional, Set

from google.adk.tools.retrieval.vertex_ai_rag_retrieval import VertexAiRagRetrieval
from google.adk.tools.tool_context import ToolContext
from google.cloud import storage
from vertexai.preview import rag
from typing_extensions import override

logger = logging.getLogger(__name__)


class VertexAiRagRetrievalWithDocs(VertexAiRagRetrieval):
    """
    Extended Vertex AI RAG Retrieval tool that can retrieve full documents.

    If result_mode is 'documents', it fetches the full content of the retrieved
    documents from GCS instead of returning just the chunks.
    """

    def __init__(
        self,
        *,
        name: str,
        description: str,
        rag_corpora: List[str] = None,
        rag_resources: List[rag.RagResource] = None,
        similarity_top_k: int = None,
        vector_distance_threshold: float = None,
        result_mode: str = "chunks",
    ):
        super().__init__(
            name=name,
            description=description,
            rag_corpora=rag_corpora,
            rag_resources=rag_resources,
            similarity_top_k=similarity_top_k,
            vector_distance_threshold=vector_distance_threshold,
        )
        self.result_mode = result_mode
        self._storage_client = None

    @property
    def storage_client(self):
        if self._storage_client is None:
            self._storage_client = storage.Client()
        return self._storage_client

    def _get_gcs_content(self, gcs_uri: str) -> str:
        """Downloads and returns content from a GCS URI."""
        try:
            # gcs_uri format: gs://bucket-name/path/to/blob
            if not gcs_uri.startswith("gs://"):
                logger.warning(f"Invalid GCS URI: {gcs_uri}")
                return ""

            parts = gcs_uri[5:].split("/", 1)
            if len(parts) != 2:
                logger.warning(f"Invalid GCS URI format: {gcs_uri}")
                return ""

            bucket_name, blob_name = parts
            bucket = self.storage_client.bucket(bucket_name)
            blob = bucket.blob(blob_name)

            content = blob.download_as_text()
            logger.info(f"Downloaded document from {gcs_uri}")
            return content
        except Exception as e:
            logger.error(f"Error downloading from GCS {gcs_uri}: {e}")
            return f"Error retrieving document: {e}"

    @override
    async def run_async(
        self,
        *,
        args: dict[str, Any],
        tool_context: ToolContext,
    ) -> Any:
        # Perform the standard retrieval query
        response = rag.retrieval_query(
            text=args['query'],
            rag_resources=self.vertex_rag_store.rag_resources,
            rag_corpora=self.vertex_rag_store.rag_corpora,
            similarity_top_k=self.vertex_rag_store.similarity_top_k,
            vector_distance_threshold=self.vertex_rag_store.vector_distance_threshold,
        )

        logging.debug('RAG raw response: %s', response)

        if not response.contexts.contexts:
            return f'No matching result found with the config: {self.vertex_rag_store}'

        # If result_mode is chunks (default), return chunks as text
        if self.result_mode != "documents":
            return [context.text for context in response.contexts.contexts]

        # If result_mode is documents, fetch full documents
        logger.info("Fetching full documents for RAG results...")

        # Extract unique source URIs
        unique_uris: Set[str] = set()
        for context in response.contexts.contexts:
            if context.source_uri:
                unique_uris.add(context.source_uri)
            # Try to handle RagFile case if source_uri is missing but display_name is present
            # Note: This is a best-effort approach. source_uri is most reliable.

        if not unique_uris:
            logger.warning("No source URIs found in RAG context.")
            return [context.text for context in response.contexts.contexts]

        full_documents = []
        for uri in unique_uris:
            if uri.startswith("gs://"):
                content = self._get_gcs_content(uri)
                if content:
                    full_documents.append(f"Document: {uri}\n\n{content}")
            else:
                # Assuming the user's snippet about getting file by name might apply here
                # if we have a file name but not a gs:// URI directly in context.
                # However, context.source_uri is typically the GCS URI for imported files.
                logger.warning(f"Skipping non-GCS URI: {uri}")
                full_documents.append(f"Document reference: {uri} (Content not retrieved)")

        if not full_documents:
             return [context.text for context in response.contexts.contexts]

        return full_documents
