#pragma once

class virtual_buffer_t
{
public:
	virtual_buffer_t();
	virtual_buffer_t(size_t size);
	~virtual_buffer_t();
	void * GetSpace(size_t needSize);
	size_t GetLength() { return m_cbSize; }
	void * GetBuffer() { return m_pBuffer; }
	void * at(size_t offset) { return (void*)((uintptr_t)m_pBuffer + offset); }

	void * m_pBuffer;
	size_t m_cbSize;
};

class virtual_buffer_based_t : public virtual_buffer_t
{
public:
	virtual_buffer_based_t(size_t size, uintptr_t base);
	uintptr_t GetBase() { return m_base; }
	void * atAddress(uintptr_t address) { return (void*)((uintptr_t)m_pBuffer + address - m_base); }

	uintptr_t m_base;
};


class crt_buffer_t
{
public:
	crt_buffer_t();
	crt_buffer_t(size_t size);
	~crt_buffer_t();
	void * GetSpace(size_t needSize);
	size_t GetLength() { return m_cbSize; }
	void * GetBuffer() { return m_pBuffer; }

	void * m_pBuffer;
	size_t m_cbSize;
};