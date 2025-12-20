"""
Test for VertexAiRagRetrievalWithDocs
"""
import unittest
from unittest.mock import MagicMock, patch, AsyncMock
from types import SimpleNamespace

# Mock necessary modules before importing the tool
import sys

# Mock google.adk.tools.retrieval.vertex_ai_rag_retrieval
class MockVertexAiRagRetrieval:
    def __init__(self, **kwargs):
        self.vertex_rag_store = SimpleNamespace(
            rag_resources=kwargs.get('rag_resources'),
            rag_corpora=kwargs.get('rag_corpora'),
            similarity_top_k=kwargs.get('similarity_top_k'),
            vector_distance_threshold=kwargs.get('vector_distance_threshold')
        )

    async def run_async(self, **kwargs):
        pass

# Mock vertexai.preview.rag
mock_rag = MagicMock()
mock_rag.RagResource = MagicMock()

# Setup mocks in sys.modules
sys.modules['google.adk.tools.retrieval.vertex_ai_rag_retrieval'] = MagicMock()
sys.modules['google.adk.tools.retrieval.vertex_ai_rag_retrieval'].VertexAiRagRetrieval = MockVertexAiRagRetrieval
sys.modules['vertexai.preview.rag'] = mock_rag
sys.modules['vertexai'] = MagicMock()
sys.modules['vertexai.preview'] = MagicMock()
sys.modules['vertexai.preview'].rag = mock_rag

# Now import the tool to be tested
from soc_agent.tools.vertex_ai_rag_tool import VertexAiRagRetrievalWithDocs

class TestVertexAiRagRetrievalWithDocs(unittest.IsolatedAsyncioTestCase):

    async def test_run_async_chunks_mode(self):
        """Test default chunks mode."""
        tool = VertexAiRagRetrievalWithDocs(
            name="test_tool",
            description="test",
            result_mode="chunks"
        )

        # Mock retrieval_query response
        mock_response = MagicMock()
        context = MagicMock()
        context.text = "chunk text"
        context.source_uri = "gs://bucket/file.pdf"
        mock_response.contexts.contexts = [context]

        mock_rag.retrieval_query.return_value = mock_response

        result = await tool.run_async(
            args={"query": "test query"},
            tool_context=MagicMock()
        )

        self.assertEqual(result, ["chunk text"])
        mock_rag.retrieval_query.assert_called_once()

    @patch("soc_agent.tools.vertex_ai_rag_tool.storage.Client")
    async def test_run_async_documents_mode(self, mock_storage_client):
        """Test documents mode with GCS download."""
        tool = VertexAiRagRetrievalWithDocs(
            name="test_tool",
            description="test",
            result_mode="documents"
        )

        # Mock retrieval_query response
        mock_response = MagicMock()
        context = MagicMock()
        context.text = "chunk text"
        context.source_uri = "gs://bucket/file.pdf"
        mock_response.contexts.contexts = [context]

        mock_rag.retrieval_query.return_value = mock_response

        # Mock Storage Client
        mock_bucket = MagicMock()
        mock_blob = MagicMock()
        mock_blob.download_as_text.return_value = "Full document content"
        mock_bucket.blob.return_value = mock_blob
        mock_storage_client.return_value.bucket.return_value = mock_bucket

        result = await tool.run_async(
            args={"query": "test query"},
            tool_context=MagicMock()
        )

        self.assertEqual(len(result), 1)
        self.assertIn("Document: gs://bucket/file.pdf", result[0])
        self.assertIn("Full document content", result[0])

        # Verify storage client usage
        mock_storage_client.return_value.bucket.assert_called_with("bucket")
        mock_bucket.blob.assert_called_with("file.pdf")
        mock_blob.download_as_text.assert_called_once()

    @patch("soc_agent.tools.vertex_ai_rag_tool.storage.Client")
    async def test_run_async_documents_mode_invalid_uri(self, mock_storage_client):
        """Test documents mode with non-GCS URI."""
        tool = VertexAiRagRetrievalWithDocs(
            name="test_tool",
            description="test",
            result_mode="documents"
        )

        # Mock retrieval_query response
        mock_response = MagicMock()
        context = MagicMock()
        context.text = "chunk text"
        context.source_uri = "http://example.com/file.pdf"
        mock_response.contexts.contexts = [context]

        mock_rag.retrieval_query.return_value = mock_response

        result = await tool.run_async(
            args={"query": "test query"},
            tool_context=MagicMock()
        )

        # Should fallback to or return a message about non-GCS URI
        self.assertEqual(len(result), 1)
        self.assertIn("Document reference: http://example.com/file.pdf", result[0])
        self.assertIn("Content not retrieved", result[0])

        # Verify storage client was NOT used for download
        mock_storage_client.return_value.bucket.assert_not_called()

if __name__ == '__main__':
    unittest.main()
