"""
Database Schemas for Grocery & General Store

Each Pydantic model represents a MongoDB collection. The collection name is the lowercase of the class name.

Collections:
- Category
- Product
- Customer
- Order
"""

from pydantic import BaseModel, Field
from typing import List, Optional


class Category(BaseModel):
    name: str = Field(..., description="Category name (e.g., Produce, Dairy, Household)")
    slug: str = Field(..., description="URL-friendly unique identifier")
    icon: Optional[str] = Field(None, description="Optional icon name for UI")


class ProductVariant(BaseModel):
    name: str = Field(..., description="Variant label (e.g., 1L, 500g, pack of 6)")
    price: float = Field(..., ge=0, description="Price for this variant")
    sku: Optional[str] = Field(None, description="SKU or barcode")
    stock: int = Field(0, ge=0, description="Units available for this variant")


class Product(BaseModel):
    title: str = Field(..., description="Product title")
    description: Optional[str] = Field(None, description="Product description")
    category: str = Field(..., description="Category slug this product belongs to")
    price: float = Field(..., ge=0, description="Base price if variants are not used")
    unit: Optional[str] = Field(None, description="Unit of measure (e.g., kg, L, pcs)")
    image: Optional[str] = Field(None, description="Image URL")
    barcode: Optional[str] = Field(None, description="Barcode/UPC/EAN")
    variants: Optional[List[ProductVariant]] = Field(None, description="Optional variants with stock and pricing")
    stock: int = Field(0, ge=0, description="Stock if not using variants")
    is_active: bool = Field(True, description="Whether product is available for sale")


class Customer(BaseModel):
    name: str
    phone: Optional[str] = None
    email: Optional[str] = None
    address: Optional[str] = None


class OrderItem(BaseModel):
    product_id: str = Field(..., description="ID of the product")
    title: str
    quantity: int = Field(..., ge=1)
    price: float = Field(..., ge=0)
    variant: Optional[str] = Field(None, description="Variant name if applicable")


class Order(BaseModel):
    customer: Customer
    items: List[OrderItem]
    subtotal: float = Field(..., ge=0)
    discount: float = Field(0, ge=0)
    tax: float = Field(0, ge=0)
    total: float = Field(..., ge=0)
    status: str = Field("pending", description="pending | paid | fulfilled | cancelled")
    notes: Optional[str] = None
